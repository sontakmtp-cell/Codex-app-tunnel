"""Project boundary and durable, compare-before-write change journal."""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import sqlite3
import stat
import tempfile
import threading
import time
import uuid

from runtime import BridgeError

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_LIST_RESULTS = 500
DEFAULT_MAX_TASK_TIMEOUT = 300
MAX_OUTPUT_CHARS = 20000
SENSITIVE_DIRECTORIES = {".codex", ".agents", ".ssh", ".aws", ".azure", ".gnupg"}
BLOCKED_DIRECTORIES = SENSITIVE_DIRECTORIES | {".git", ".venv", "venv", "node_modules", "__pycache__",
                                              ".pytest_cache", ".mypy_cache"}
BLOCKED_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".crt", ".cer", ".env", ".der", ".jks", ".keystore", ".kdbx", ".p7b"}
SECRET_PREFIXES = (".env", "credentials", "secrets", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
SECRET_NAMES = {"auth.json", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials"}
ALLOWED_EXECUTABLES = {"cargo", "dotnet", "go", "git", "mypy", "node", "npm", "npx", "pnpm",
                       "pytest", "py", "python", "ruff", "uv", "yarn"}
BLOCKED_COMMAND_WORDS = {"checkout", "clean", "del", "format", "iex", "invoke-expression", "kill",
                         "push", "remove-item", "reset", "restore", "rm", "shutdown", "stop-process", "taskkill"}
BLOCKED_COMMAND_FLAGS = {"--eval", "--exec", "/c", "/k", "-c", "-e"}


def _sha256(data: bytes | None):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _redact(value: str) -> str:
    value = re.sub(r"(?i)\bsk-[A-Za-z0-9_-]{16,}", "[REDACTED]", value)
    return re.sub(r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,}]+", r"\1[REDACTED]", value)


def _bounded(value, limit=MAX_OUTPUT_CHARS):
    value = _redact(value)
    return value[:limit], len(value) > limit


def integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise BridgeError(f"INVALID_INPUT: {name} must be between {minimum} and {maximum}.")
    return value


def request_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value):
        raise BridgeError("INVALID_INPUT: request_id needs 8-128 letters, numbers, underscores or hyphens.")
    return value


def _validate_command(argv, task_id):
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(v, str) and v.strip() and "\x00" not in v for v in argv):
        raise BridgeError(f"INVALID_CONFIG: task {task_id} needs an argv list.")
    if Path(argv[0]).stem.lower() not in ALLOWED_EXECUTABLES:
        raise BridgeError(f"INVALID_CONFIG: blocked executable for {task_id}.")
    if any(v.lower() in BLOCKED_COMMAND_FLAGS | BLOCKED_COMMAND_WORDS for v in argv[1:]):
        raise BridgeError(f"INVALID_CONFIG: blocked argument in {task_id}.")
    return tuple(argv)


@dataclass(frozen=True)
class BridgeConfig:
    workspace_root: Path
    tasks: dict[str, tuple[str, ...]]
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_list_results: int = DEFAULT_MAX_LIST_RESULTS
    max_task_timeout_seconds: int = DEFAULT_MAX_TASK_TIMEOUT
    state_dir: Path | None = None
    codex_executable: str | None = None
    runtime_read_roots: tuple[Path, ...] = ()
    completed_changes_to_keep: int = 30


def load_config(path: Path):
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        root = Path(raw["workspace_root"])
        if not root.is_absolute() or not root.is_dir():
            raise ValueError()
        check_link_chain(root)
        root = root.resolve()
        # The editable project must not contain the bridge, config, or private journal.
        if Path(__file__).resolve().is_relative_to(root) or path.resolve().is_relative_to(root):
            raise BridgeError("INVALID_CONFIG: project must not contain the bridge or its configuration.")
        tasks = raw.get("tasks", {})
        if not isinstance(tasks, dict):
            raise ValueError()
        for name in tasks:
            if not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", name):
                raise ValueError()
        state = Path(raw.get("state_dir", str(path.parent / ".state" / _sha256(str(root).lower().encode())[:16])))
        if not state.is_absolute() or state.resolve().is_relative_to(root):
            raise BridgeError("INVALID_CONFIG: state_dir must be absolute and outside the project.")
        runtime_roots = tuple(Path(p) for p in raw.get("runtime_read_roots", []))
        if any(not p.is_absolute() or not p.is_dir() or p == Path(p.anchor) for p in runtime_roots):
            raise ValueError()
        return BridgeConfig(root, {k: _validate_command(v, k) for k, v in tasks.items()},
            integer(raw.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES), "max_file_bytes", 1, 10*1024*1024),
            integer(raw.get("max_list_results", 500), "max_list_results", 1, 2000),
            integer(raw.get("max_task_timeout_seconds", 300), "max_task_timeout_seconds", 1, 900),
            state.resolve(), raw.get("codex_executable"), runtime_roots,
            integer(raw.get("completed_changes_to_keep", 30), "completed_changes_to_keep", 1, 300))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, BridgeError):
            raise
        raise BridgeError("INVALID_CONFIG: check the local JSON paths, limits and task lists.") from exc


def check_link_chain(path: Path):
    for entry in [*reversed(path.parents), path]:
        try:
            info = entry.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BridgeError("PATH_BLOCKED: symlinks, junctions and reparse points are not allowed.")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise BridgeError("PATH_BLOCKED: hardlinked files are not allowed.")


def git_repository(root: Path):
    try:
        for path in (root/".git/HEAD",root/".git/objects"):
            check_link_chain(path)
        return (root/".git/HEAD").is_file() and (root/".git/objects").is_dir()
    except BridgeError:
        return False


class ProjectFiles:
    def __init__(self, config):
        self.config, self.root = config, config.workspace_root

    @staticmethod
    def _is_blocked(relative):
        parts = [p.lower() for p in Path(relative).parts]
        return any(p in BLOCKED_DIRECTORIES or p in SECRET_NAMES or p.startswith(SECRET_PREFIXES)
                   or Path(p).suffix in BLOCKED_SUFFIXES for p in parts)

    def _relative(self, raw, *, allow_missing=False):
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise BridgeError("PATH_BLOCKED: use a non-empty project-relative path.")
        win = PureWindowsPath(raw)
        parts = raw.replace("\\", "/").split("/")
        if win.drive or raw.startswith(("/", "\\")) or len(parts) > 32 or any(
            p in ("", ".", "..") or p[-1:] in (".", " ") or re.search(r'[<>:"|?*\x00-\x1f]', p)
            or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p) for p in parts):
            raise BridgeError("PATH_BLOCKED: unsafe Windows path, stream, device or parent segment.")
        relative = Path(*parts)
        if self._is_blocked(relative):
            raise BridgeError("PATH_BLOCKED: protected file or directory.")
        target = self.root / relative
        check_link_chain(target)
        if not target.resolve().is_relative_to(self.root):
            raise BridgeError("PATH_BLOCKED: path escapes the project.")
        if not allow_missing and not target.exists():
            raise BridgeError(f"NOT_FOUND: {relative.as_posix()}")
        return target, relative.as_posix()

    def _file(self, raw, *, allow_missing=False):
        target, relative = self._relative(raw, allow_missing=allow_missing)
        if target.exists() and not target.is_file():
            raise BridgeError(f"INVALID_FILE: {relative}")
        return target, relative

    def _text(self, data):
        if len(data) > self.config.max_file_bytes:
            raise BridgeError("FILE_TOO_LARGE: increase the local limit if needed.")
        if b"\x00" in data:
            raise BridgeError("BINARY_BLOCKED: only UTF-8 text files are supported.")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BridgeError("BINARY_BLOCKED: only UTF-8 text files are supported.") from exc

    def _read_bytes(self, raw):
        target, relative = self._file(raw)
        with target.open("rb") as f:
            info = os.fstat(f.fileno())
            if info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                raise BridgeError("PATH_BLOCKED: unsafe file handle.")
            data = f.read(self.config.max_file_bytes + 1)
        self._text(data)
        check_link_chain(target)
        return target, relative, data

    def list_files(self, prefix="", max_results=500):
        integer(max_results, "max_results", 1, self.config.max_list_results)
        base = self._relative(prefix)[0] if prefix else self.root
        if not base.is_dir():
            raise BridgeError("INVALID_INPUT: prefix must be a directory.")
        files = []
        for folder, dirs, names in os.walk(base, followlinks=False):
            def safe(name):
                try:
                    self._relative((Path(folder) / name).relative_to(self.root).as_posix())
                    return True
                except BridgeError:
                    return False
            dirs[:] = sorted(d for d in dirs if safe(d))
            for name in sorted(names):
                if safe(name):
                    files.append((Path(folder) / name).relative_to(self.root).as_posix())
                    if len(files) > max_results:
                        return {"workspace_root": self.root.as_posix(), "files": files[:max_results], "truncated": True}
        return {"workspace_root": self.root.as_posix(), "files": files, "truncated": False}

    def read_file(self, raw, start_line=1, max_bytes=DEFAULT_MAX_FILE_BYTES, end_line=None):
        integer(start_line, "start_line", 1, 2**31)
        integer(max_bytes, "max_bytes", 1, self.config.max_file_bytes)
        if end_line is not None:
            integer(end_line, "end_line", start_line, 2**31)
        _, relative, data = self._read_bytes(raw)
        lines = data.decode("utf-8").splitlines(keepends=True)
        selected = "".join(lines[start_line-1:end_line]).encode("utf-8")
        content = selected[:max_bytes].decode("utf-8", errors="ignore")
        last_line = start_line + len(content.splitlines()) - 1
        partial = len(selected) > max_bytes and not content.endswith(("\n", "\r"))
        return {"path": relative, "sha256": _sha256(data), "content": content, "start_line": start_line,
                "end_line": last_line, "total_lines": len(lines), "partial_last_line": partial,
                "next_line": (last_line if partial else last_line+1) if last_line < len(lines) or partial else None,
                "truncated": len(selected) > max_bytes or (end_line is not None and end_line < len(lines))}

    @staticmethod
    def _atomic_write(target, data, before_replace=None):
        fd, name = tempfile.mkstemp(prefix=".mcp-bridge-", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            if before_replace:
                before_replace()
            check_link_chain(target)
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)


class ChangeJournal(ProjectFiles):
    def __init__(self, config):
        super().__init__(config)
        self.lock = threading.RLock()
        self.active_run = None
        self.state = config.state_dir or Path(__file__).resolve().parent / ".state" / _sha256(str(self.root).encode())[:16]
        if self.state.resolve().is_relative_to(self.root):
            raise BridgeError("INVALID_CONFIG: journal must be outside the project.")
        check_link_chain(self.state)
        self.state.mkdir(parents=True, exist_ok=True)
        self._lock_file = (self.state / "bridge.lock").open("a+b")
        self._lock_file.seek(0)
        self._lock_file.write(b"1")
        self._lock_file.flush()
        self._lock_file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._lock_file.close()
            raise BridgeError("BRIDGE_BUSY: this project already has an active bridge.") from exc
        self.db = sqlite3.connect(self.state / "journal.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS changes (
                id TEXT PRIMARY KEY, request_id TEXT UNIQUE, fingerprint TEXT, title TEXT,
                status TEXT, created REAL, updated REAL, error TEXT);
            CREATE TABLE IF NOT EXISTS files (
                change_id TEXT, path TEXT, before BLOB, after BLOB, before_sha TEXT, after_sha TEXT,
                phase TEXT NOT NULL DEFAULT 'pending',
                PRIMARY KEY(change_id,path));
            CREATE TABLE IF NOT EXISTS operations (request_id TEXT PRIMARY KEY, kind TEXT, target TEXT);
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, request_id TEXT UNIQUE, task_id TEXT, timeout INTEGER,
                status TEXT, started REAL, ended REAL, exit_code INTEGER, error TEXT);
        """)
        if "phase" not in {r[1] for r in self.db.execute("PRAGMA table_info(files)")}:
            self.db.execute("ALTER TABLE files ADD COLUMN phase TEXT NOT NULL DEFAULT 'pending'")
            self.db.execute("UPDATE changes SET status='recovery_conflict',error='Legacy interrupted journal lacks per-file progress; inspect locally.' WHERE status IN ('applying','undoing')")
        saved_root = self.db.execute("SELECT value FROM metadata WHERE key='workspace_root'").fetchone()
        identity = os.path.normcase(str(self.root.resolve()))
        if saved_root and saved_root[0] != identity:
            self.close_journal()
            raise BridgeError("INVALID_CONFIG: this journal belongs to another project.")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('workspace_root',?)", (identity,))
        self.db.execute("UPDATE runs SET status='runtime_lost', ended=?, error='Bridge restarted; task was not replayed.' WHERE ended IS NULL", (time.time(),))
        self.db.commit()
        self.recover()

    def close_journal(self):
        self.db.close()
        self._lock_file.close()

    def _idle(self):
        if self.active_run:
            raise BridgeError("TASK_BUSY: stop or wait for the active task before changing files.")
        if self.db.execute("SELECT 1 FROM changes WHERE status='recovery_conflict'").fetchone():
            raise BridgeError("RECOVERY_CONFLICT: resolve the journal conflict locally before another write.")

    def _current(self, relative):
        target, _ = self._file(relative, allow_missing=True)
        return self._read_bytes(relative)[2] if target.exists() else None

    def prepare_changes(self, title, edits, request_id):
        request_key(request_id)
        if not isinstance(title, str) or not 1 <= len(title) <= 160:
            raise BridgeError("INVALID_INPUT: title needs 1-160 characters.")
        if not isinstance(edits, list) or not 1 <= len(edits) <= 100:
            raise BridgeError("INVALID_INPUT: provide 1-100 file edits.")
        fingerprint = _sha256(json.dumps([title, edits], sort_keys=True, ensure_ascii=False).encode())
        with self.lock:
            old = self.db.execute("SELECT id,fingerprint FROM changes WHERE request_id=?", (request_id,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise BridgeError("IDEMPOTENCY_CONFLICT: request_id already describes another change.")
                return self.get_change(old["id"])
            records, seen, total = [], set(), 0
            for edit in edits:
                if not isinstance(edit, dict) or set(edit) - {"path", "content", "old_text", "new_text", "expected_sha256"}:
                    raise BridgeError("INVALID_INPUT: unknown edit fields.")
                target, relative = self._file(edit.get("path"), allow_missing=True)
                if relative.casefold() in seen:
                    raise BridgeError("INVALID_INPUT: duplicate path in change.")
                seen.add(relative.casefold())
                before = self._current(relative)
                expected = edit.get("expected_sha256")
                if expected is not None and not isinstance(expected, str):
                    raise BridgeError("INVALID_INPUT: expected_sha256 must be a string or null.")
                expected = expected.lower() if expected else None
                if expected != _sha256(before):
                    raise BridgeError(f"SHA_CONFLICT: {relative}")
                if "content" in edit:
                    if "old_text" in edit or "new_text" in edit:
                        raise BridgeError("INVALID_INPUT: choose replacement or exact patch.")
                    content = edit["content"]
                else:
                    old_text, new_text = edit.get("old_text"), edit.get("new_text")
                    current = self._text(before) if before is not None else ""
                    if not isinstance(old_text, str) or not old_text or current.count(old_text) != 1:
                        raise BridgeError(f"PATCH_AMBIGUOUS: old_text must match exactly once in {relative}.")
                    if not isinstance(new_text, str):
                        raise BridgeError("INVALID_INPUT: new_text must be text.")
                    content = current.replace(old_text, new_text, 1)
                if not isinstance(content, str):
                    raise BridgeError("INVALID_INPUT: content must be text.")
                after = content.encode("utf-8")
                self._text(after)
                if not target.parent.is_dir():
                    raise BridgeError(f"NOT_FOUND: parent directory of {relative} must exist.")
                if before == after:
                    raise BridgeError(f"NO_CHANGE: {relative}")
                total += len(before or b"") + len(after)
                if total > 16*1024*1024:
                    raise BridgeError("CHANGE_TOO_LARGE: maximum 16 MiB before plus after.")
                records.append((relative, before, after, _sha256(before), _sha256(after)))
            change_id, now = uuid.uuid4().hex, time.time()
            with self.db:
                self.db.execute("INSERT INTO changes VALUES (?,?,?,?,?,?,?,?)",
                    (change_id, request_id, fingerprint, title, "prepared", now, now, None))
                self.db.executemany("INSERT INTO files (change_id,path,before,after,before_sha,after_sha) VALUES (?,?,?,?,?,?)", [(change_id, *row) for row in records])
            return self.get_change(change_id)

    def _rows(self, change_id):
        change = self.db.execute("SELECT * FROM changes WHERE id=?", (change_id,)).fetchone()
        if not change:
            raise BridgeError("NOT_FOUND: unknown change_id.")
        return change, self.db.execute("SELECT * FROM files WHERE change_id=? ORDER BY path", (change_id,)).fetchall()

    def list_changes(self, limit=30):
        integer(limit, "limit", 1, 100)
        with self.lock:
            return {"changes": [dict(row) for row in self.db.execute(
                "SELECT id,title,status,created,updated,error FROM changes ORDER BY created DESC LIMIT ?", (limit,))]}

    def get_change(self, change_id, path=None, offset=0, max_chars=20000):
        integer(offset, "offset", 0, 32*1024*1024)
        integer(max_chars, "max_chars", 1, 50000)
        with self.lock:
            change, rows = self._rows(change_id)
            files, chunks = [], []
            for row in rows:
                self._file(row["path"], allow_missing=True)
                files.append({"path": row["path"], "before_sha256": row["before_sha"], "after_sha256": row["after_sha"],
                              "created": row["before"] is None})
                if path is None or path == row["path"]:
                    chunks.extend(difflib.unified_diff(self._text(row["before"] or b"").splitlines(keepends=True),
                                  self._text(row["after"]).splitlines(keepends=True),
                                  fromfile="a/"+row["path"] if row["before"] is not None else "/dev/null",
                                  tofile="b/"+row["path"]))
            if path and path not in [f["path"] for f in files]:
                raise BridgeError("NOT_FOUND: file is not in the change.")
            diff = _redact("".join(chunks))
            return {"change_id": change_id, "title": change["title"], "status": change["status"],
                    "error": change["error"], "files": files, "diff": diff[offset:offset+max_chars],
                    "next_offset": offset+max_chars if offset+max_chars < len(diff) else None}

    def _operation(self, request_id, kind, change_id):
        request_key(request_id)
        row = self.db.execute("SELECT kind,target FROM operations WHERE request_id=?", (request_id,)).fetchone()
        if row and tuple(row) != (kind, change_id):
            raise BridgeError("IDEMPOTENCY_CONFLICT: request_id already used for another operation.")
        return row is not None

    def _verify(self, rows, side):
        conflicts = []
        for row in rows:
            try:
                if _sha256(self._current(row["path"])) != row[side+"_sha"]:
                    conflicts.append(row["path"])
            except BridgeError:
                conflicts.append(row["path"])
        if conflicts:
            raise BridgeError("SHA_CONFLICT: " + ", ".join(conflicts))

    def _write_checked(self, row, source, dest):
        self._verify([row], source)
        target, _ = self._file(row["path"], allow_missing=True)
        if row[dest] is None:
            target.unlink()
        else:
            self._atomic_write(target, row[dest], lambda: self._verify([row], source))

    def _set_status(self, change_id, status, error=None):
        with self.db:
            self.db.execute("UPDATE changes SET status=?,error=?,updated=? WHERE id=?", (status,error,time.time(),change_id))

    def _mutate(self, change_id, request_id, undo=False):
        with self.lock:
            kind = "undo" if undo else "apply"
            replay = self._operation(request_id, kind, change_id)
            change, rows = self._rows(change_id)
            if replay:
                return self.get_change(change_id)
            self._idle()
            required, source, dest = ("applied", "after", "before") if undo else ("prepared", "before", "after")
            if change["status"] != required:
                raise BridgeError(f"CHANGE_STATE: expected {required}; found {change['status']}.")
            self._verify(rows, source)
            with self.db:
                self.db.execute("INSERT INTO operations VALUES (?,?,?)", (request_id,kind,change_id))
                self.db.execute("UPDATE changes SET status=?,updated=? WHERE id=?", ("undoing" if undo else "applying",time.time(),change_id))
                self.db.execute("UPDATE files SET phase='pending' WHERE change_id=?", (change_id,))
            try:
                for row in rows:
                    self._verify([row], source)
                    with self.db:
                        self.db.execute("UPDATE files SET phase='writing' WHERE change_id=? AND path=?", (change_id,row["path"]))
                    self._write_checked(row, source, dest)
                    with self.db:
                        self.db.execute("UPDATE files SET phase='written' WHERE change_id=? AND path=?", (change_id,row["path"]))
            except Exception:
                self._recover_one(change_id)
                raise BridgeError("WRITE_FAILED: inspected journal recovery; read this change's status.") from None
            self._set_status(change_id, "undone" if undo else "applied")
            result = self.get_change(change_id)
            self._prune()
            return result

    def apply_changes(self, change_id, request_id):
        return self._mutate(change_id, request_id)

    def undo_changes(self, change_id, request_id):
        return self._mutate(change_id, request_id, True)

    def _recover_one(self, change_id):
        change, rows = self._rows(change_id)
        latest = self.db.execute("SELECT kind FROM operations WHERE target=? AND kind IN ('apply','undo') ORDER BY rowid DESC LIMIT 1", (change_id,)).fetchone()
        undo = change["status"] == "undoing" or (change["status"] == "recovery_conflict" and latest and latest[0] == "undo")
        original, partial = ("after", "before") if undo else ("before", "after")
        conflicts = []
        for row in reversed(rows):
            try:
                current = _sha256(self._current(row["path"]))
                if current == row[original+"_sha"]:
                    continue
                if row["phase"] == "pending":
                    # This file was never attempted; matching our planned content is not proof we wrote it.
                    conflicts.append(row["path"])
                    continue
                if current != row[partial+"_sha"]:
                    conflicts.append(row["path"])
                    continue
                self._write_checked(row, partial, original)
            except (OSError, BridgeError):
                conflicts.append(row["path"])
        self._set_status(change_id, "recovery_conflict" if conflicts else ("undo_failed" if undo else "recovered"),
                         "Conflict: " + ", ".join(conflicts) if conflicts else "Interrupted operation rolled back with SHA checks.")

    def recover(self):
        with self.lock:
            for row in self.db.execute("SELECT id FROM changes WHERE status IN ('applying','undoing','recovery_conflict')").fetchall():
                self._recover_one(row["id"])

    def _prune(self):
        # Keep failures and unfinished batches regardless of age.
        ids = [r[0] for r in self.db.execute("SELECT id FROM changes WHERE status IN ('applied','undone') ORDER BY updated DESC LIMIT -1 OFFSET ?", (self.config.completed_changes_to_keep,))]
        with self.db:
            for change_id in ids:
                self.db.execute("DELETE FROM files WHERE change_id=?", (change_id,))
                # Retain small idempotency tombstones, never the old file contents.
                self.db.execute("UPDATE changes SET status='expired' WHERE id=?", (change_id,))

    def write_file(self, raw_path, content, expected_sha256=None):
        edit = {"path": raw_path, "content": content, "expected_sha256": expected_sha256}
        key = _sha256(json.dumps(edit,sort_keys=True).encode())
        change = self.prepare_changes("Write " + raw_path[:150], [edit], "legacy-"+key)
        result = self.apply_changes(change["change_id"], "legacy-apply-"+key)
        if result["status"] != "applied":
            raise BridgeError("CHANGE_STATE: the original legacy request is no longer applied; prepare a new change explicitly.")
        return {"path": raw_path, "sha256": _sha256(content.encode()), "bytes_written": len(content.encode()),
                "change_id": result["change_id"], "status": result["status"]}

    def apply_patch(self, raw_path, old_text, new_text, expected_sha256):
        edit = {"path": raw_path, "old_text": old_text, "new_text": new_text, "expected_sha256": expected_sha256}
        key = _sha256(json.dumps(edit,sort_keys=True).encode())
        change = self.prepare_changes("Patch " + raw_path[:150], [edit], "legacy-"+key)
        result = self.apply_changes(change["change_id"], "legacy-apply-"+key)
        if result["status"] != "applied":
            raise BridgeError("CHANGE_STATE: the original legacy request is no longer applied; prepare a new change explicitly.")
        return {"path": raw_path, "sha256": result["files"][0]["after_sha256"], "change_id": result["change_id"], "status": result["status"]}

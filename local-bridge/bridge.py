"""Bridge capabilities. Every remote input is scoped here before an RPC."""
import base64
from datetime import datetime, timezone
from contextlib import nullcontext
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid
from urllib.parse import urlparse

from files import (BridgeConfig, BridgeError, ChangeJournal, ProjectFiles, _bounded, _redact,
                   _sha256, check_link_chain, git_repository, integer, load_config, request_key)
from runtime import AppServer
from security_mcp import SecurityMcpIdempotencyConflict, SecurityMcpTimeout
from tasks import TaskRunner


_SECURITY_MODES = {"standard", "chatgpt_deep"}
_SECURITY_TARGETS = {"codebase", "changes"}
_SECURITY_TERMINAL = {"cancelled", "failed", "completed"}
_SECURITY_STANDARD_PHASES = (
    "preflight", "inventory", "threat_model", "discovery", "validation",
    "attack_path", "finalization",
)
_SECURITY_DEEP_PHASES = (
    "preflight", "inventory", "threat_model", "attack_surface",
    "auth_data_flow", "injection_file_process_network_state", "deduplicate",
    "validation", "attack_path", "finalization",
)
_SECURITY_PHASE_FIELDS = {
    "preflight": {"coverage"},
    "inventory": {"inventory", "coverage", "boundaries"},
    "threat_model": {"threatModel", "coverage"},
    "discovery": {"candidates", "coverage"},
    "attack_surface": {"candidates", "coverage"},
    "auth_data_flow": {"candidates", "coverage"},
    "injection_file_process_network_state": {"candidates", "coverage"},
    "deduplicate": {"candidates", "coverage"},
    "validation": {"validations", "coverage"},
    "attack_path": {"attackPaths", "coverage"},
    "finalization": {"findings", "coverage"},
}
_SECURITY_FORMATS = {"json", "sarif", "markdown"}
_SECURITY_SENSITIVE_KEYS = {
    "scandir", "scan_dir", "workspace_root", "root", "state_dir", "handofftoken",
    "handoff_token", "resumetoken", "resume_token", "sandbox", "secret", "secrets",
    "token", "password", "authorization", "credential", "env", "environment",
}
_SEARCH_TIME_BUDGET_SECONDS = 5.0
_SEARCH_MAX_PATTERNS = 32
_SEARCH_DEFAULT_EXCLUDES = [
    "reports/**", "report/**", "dist/**", "build/**", "coverage/**", "out/**", "artifacts/**",
    "generated/**", "assets/**", "images/**", "node_modules/**", "vendor/**", "**/.cache/**",
]


def _security_scan_key(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise BridgeError("INVALID_INPUT: invalid scan_id.")
    return value


def _security_status(value, fallback="running"):
    if not isinstance(value, str) or not value.strip():
        return fallback
    value = value.strip().lower().replace("-", "_")
    return {"complete": "completed", "canceled": "cancelled"}.get(value, value)


def _security_redact_text(value):
    value = _redact(str(value))
    # Keep safe project-relative filenames while hiding absolute locations.
    return re.sub(r"(?i)(?:[A-Za-z]:[\\/]|(?<![A-Za-z0-9])//|(?<![A-Za-z0-9])/(?!\s))[^\s,;}\]]+",
                  "[REDACTED_PATH]", value)


def datetime_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _git_bash_executable():
    if os.name == "nt":
        candidates = []
        for name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(name)
            if base:
                candidates.append(Path(base) / "Git" / "bin" / "bash.exe")
    else:
        candidates = [Path(shutil.which("bash") or "")]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise BridgeError("BASH_UNAVAILABLE: install Git for Windows or configure Git Bash locally.")


class LocalBridge(ChangeJournal):
    """Local facade plus a deliberately small direct Security adapter contract.

    ``security_adapter`` is expected to expose only these direct methods:
    ``start_scan(mode, target, user_context, request_id)`` returning a
    ``workspace.results.scanId`` response; ``get_scan(scan_id)``;
    ``continue_scan(scan_id)``; ``commit_phase(scan_id, phase, phase_data,
    request_id)``; ``complete_scan(scan_id, request_id)``;
    ``cancel_scan(scan_id, request_id)``; ``list_findings(scan_id, cursor,
    limit)``; and ``export_findings(scan_id, format)``.  It may also expose
    ``find_scan_by_request(request_id, payload_hash)`` and
    ``show_security_scan_panel()``.  These calls are direct Security MCP
    adapter calls: no App Server turn, model, reasoning setting or native
    worker is part of this contract.  A repeated ``start_scan`` with the same
    request and payload must replay the adapter journal instead of creating a
    second native scan.
    """

    def __init__(self, config, runtime=None, start_runtime=True, security_adapter=None, adapter=None):
        # Keep the old third positional ``start_runtime`` argument usable while
        # accepting a convenient positional adapter for the new facade tests.
        if security_adapter is None and adapter is not None:
            security_adapter = adapter
        if (security_adapter is None and runtime is not None and
                not hasattr(runtime, "listeners") and callable(getattr(runtime, "start_scan", None))):
            security_adapter, runtime = runtime, None
        if security_adapter is None and not isinstance(start_runtime, bool):
            security_adapter, start_runtime = start_runtime, True
        super().__init__(config)
        if security_adapter is None:
            security_adapter = getattr(runtime, "security_adapter", None)
        self.security_adapter = security_adapter
        self._init_security_journal()
        runtime_roots = [Path(sys.base_prefix), Path(sys.prefix), *config.runtime_read_roots]
        for exe in ("rg", "git"):
            resolved = shutil.which(exe)
            if resolved:
                parent = Path(resolved).resolve().parent
                runtime_roots.append(parent.parent if exe == "git" else parent)
        self.runtime = runtime or AppServer(self.root, self.state, config.codex_executable, runtime_roots,
                                            config.external_read_roots)
        self.tasks = TaskRunner(self, self.runtime)
        self.revision = 0
        self.skills = {}
        self.known_threads = set()
        self.thread_pages = {None}
        self.docs_thread = None
        self.runtime.listeners.append(self._event)
        if start_runtime and runtime is None:
            try:
                self.runtime.start()
                self.runtime.verify_policy()
            except Exception:
                self.runtime.error = "RUNTIME_UNAVAILABLE: check doctor locally; filesystem tools remain available."
                self.runtime.close()

    def close(self):
        run_id = self.active_run
        if run_id:
            self.tasks.stop_task_run(run_id, "shutdown-"+uuid.uuid4().hex)
        adapter = self.security_adapter
        if adapter is not None:
            shutdown = getattr(adapter, "shutdown", None)
            close = getattr(adapter, "close", None)
            if callable(shutdown):
                shutdown()
            elif callable(close):
                close()
        self.runtime.close()
        if run_id and not self.tasks.runs[run_id]["done"].wait(12):
            raise BridgeError("SHUTDOWN_TIMEOUT: journal remains locked until the bridge process exits.")
        self.close_journal()

    def _event(self, method, data):
        if method == "fs/changed" and data.get("watchId") == "bridge-project":
            # Only a counter reaches the UI; events may name protected paths.
            self.revision += 1

    def project_info(self):
        mode = getattr(self.runtime, "execution_mode", "normal")
        ready = self.runtime.can_execute
        command_error = None if ready else (self.runtime.command_error or None)
        return {"workspace_root": self.root.as_posix(), "git_available": shutil.which("git") is not None,
                "git_repository": git_repository(self.root),
                "runtime": {"status": self.runtime.status, "version": self.runtime.version,
                            "error": self.runtime.error, "mode": mode,
                            "mode_description": ("Turbo: command/exec dùng toàn quyền; Bash có thể đọc/ghi ngoài project và dùng mạng."
                                                 if mode == "turbo" else
                                                 "Normal: chỉ chạy task/lệnh qua policy bridge sau khi doctor đạt."),
                            "commands_enabled": ready,
                            "bash_enabled": mode == "turbo" and ready,
                            "command_error": command_error},
                "capabilities": {"changes": True, "read_file": True, "control_panel": True,
                    "search": True, "tasks": ready, "bash": mode == "turbo" and ready,
                    "watch": self.runtime.status == "connected", "skills": self.runtime.status == "connected",
                    "history": self.runtime.status == "connected", "docs": self.runtime.status == "connected"},
                "approved_tasks": list(self.config.tasks), "active_run_id": self.active_run,
                "revision": self.revision, "recovery_conflicts": [dict(r) for r in self.db.execute(
                    "SELECT id,error FROM changes WHERE status='recovery_conflict'")]}

    def set_runtime_mode(self, mode, confirm=False):
        if type(mode) is not str or mode not in {"normal", "turbo"}:
            raise BridgeError("INVALID_INPUT: mode must be normal or turbo.")
        if type(confirm) is not bool:
            raise BridgeError("INVALID_INPUT: confirm must be boolean.")
        if mode == "turbo" and not confirm:
            raise BridgeError("TURBO_CONFIRMATION_REQUIRED: confirm the full-access warning before enabling Turbo.")
        with self.lock:
            if self.active_run:
                raise BridgeError("TASK_BUSY: stop or wait for the active task before changing runtime mode.")
            if self.runtime.status != "connected":
                raise BridgeError("RUNTIME_UNAVAILABLE: cannot change mode while Codex App Server is disconnected.")
            self.runtime.execution_mode = mode
            return {"mode": mode, "project": self.project_info()}

    def run_bash(self, command, timeout_seconds=120):
        if not isinstance(command, str) or not 1 <= len(command) <= 20000 or "\x00" in command:
            raise BridgeError("INVALID_INPUT: command must be 1-20000 characters without NUL bytes.")
        integer(timeout_seconds, "timeout_seconds", 1, self.config.max_task_timeout_seconds)
        with self.lock:
            self._idle()
            if self.runtime.execution_mode != "turbo":
                raise BridgeError("TURBO_REQUIRED: enable Turbo in the control panel before running Bash.")
            self.check_command_paths()
            bash = _git_bash_executable()
            try:
                result = self.runtime.command([str(bash), "-c", command],
                                              "bash-" + uuid.uuid4().hex, timeout_seconds, stream=False)
            except BridgeError as exc:
                if str(exc).startswith("RUNTIME_REJECTED:"):
                    raise BridgeError(
                        "COMMAND_BLOCKED: runtime policy refused this command (RUNTIME_REJECTED); "
                        "use read_file or search_code_batch for read-only source inspection."
                    ) from exc
                raise
            except Exception as exc:
                raise BridgeError(
                    "COMMAND_BLOCKED: read-only source inspection is available via read_file or search_code_batch; "
                    "the runtime policy refused this command."
                ) from exc
            stdout, stdout_truncated = _bounded(result.get("stdout") or "")
            stderr, stderr_truncated = _bounded(result.get("stderr") or "")
            return {"mode": "turbo", "exit_code": result.get("exitCode"),
                    "stdout": stdout, "stderr": stderr,
                    "truncated": stdout_truncated or stderr_truncated}

    def check_command_paths(self):
        # Globs are snapshotted by Windows. Reject links/deep trees before each command.
        for folder, dirs, names in os.walk(self.root, followlinks=False):
            relative = Path(folder).relative_to(self.root)
            if len(relative.parts) > 30:
                raise BridgeError("SANDBOX_UNAVAILABLE: project exceeds the 32-level permission scan limit.")
            for name in dirs + names:
                check_link_chain(Path(folder) / name)
        check_link_chain(self.root)

    def _command_read(self, argv, timeout=30):
        with self.lock:
            self._idle()
            self.check_command_paths()
            # A read command also reserves the operation lock until it completes.
            return self.runtime.command(argv, "read-"+uuid.uuid4().hex, timeout, stream=False)

    def search_code(self, query, prefix="", file_types=None, case_sensitive=True,
                    max_results=50, cursor=0, context_lines=2):
        if not isinstance(query, str) or not 1 <= len(query) <= 500 or "\x00" in query or "\n" in query:
            raise BridgeError("INVALID_INPUT: use a single-line literal query of 1-500 characters.")
        return self._search_code([query], prefix, file_types, case_sensitive, max_results, cursor,
                                 context_lines, regex=False, include_patterns=False)

    @staticmethod
    def _search_globs(values, name):
        if values is None:
            return []
        if not isinstance(values, list) or len(values) > 32:
            raise BridgeError(f"INVALID_INPUT: {name} must contain at most 32 globs.")
        result = []
        for value in values:
            if (not isinstance(value, str) or not 1 <= len(value) <= 200 or "\x00" in value or
                    "\n" in value or Path(value).is_absolute() or ".." in Path(value).parts):
                raise BridgeError(f"INVALID_INPUT: {name} contains an unsafe glob.")
            result.append(value.replace("\\", "/"))
        return result

    def _search_candidates(self, prefix, file_types, include_globs, exclude_globs):
        base = self._relative(prefix)[0] if prefix else self.root
        if not base.is_dir():
            raise BridgeError("INVALID_INPUT: prefix must be a directory.")
        if file_types is None:
            file_types = []
        if (not isinstance(file_types, list) or len(file_types) > 20 or
                any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9]{1,16}", value)
                    for value in file_types)):
            raise BridgeError("INVALID_INPUT: file_types must be extensions such as py or ts.")
        types = {value.casefold().lstrip(".") for value in file_types}
        include_globs = self._search_globs(include_globs, "include_globs")
        exclude_globs = self._search_globs(exclude_globs, "exclude_globs")
        for folder, dirs, names in os.walk(base, followlinks=False):
            dirs[:] = sorted(name for name in dirs
                             if self._safe_relative(Path(folder) / name))
            for name in sorted(names):
                target = Path(folder) / name
                if not self._safe_relative(target):
                    continue
                try:
                    relative = target.relative_to(self.root).as_posix()
                    if target.stat().st_size > self.config.max_file_bytes:
                        continue
                except (OSError, ValueError):
                    continue
                if types and target.suffix.casefold().lstrip(".") not in types:
                    continue
                if any(fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(name, pattern)
                       for pattern in exclude_globs):
                    continue
                if include_globs and not any(fnmatch.fnmatchcase(relative, pattern) or
                                             fnmatch.fnmatchcase(name, pattern)
                                             for pattern in include_globs):
                    continue
                yield relative

    @staticmethod
    def _search_cursor_encode(file_index, line_number, skip_remaining=0):
        payload = json.dumps(
            {"version": 2, "file": file_index, "line": line_number, "skip": skip_remaining},
            separators=(",", ":"),
        ).encode("utf-8")
        return "v2:" + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _search_cursor_decode(cursor):
        if (not isinstance(cursor, str) or len(cursor) > 2000 or
                not cursor.startswith(("v1:", "v2:"))):
            raise BridgeError("INVALID_INPUT: cursor is not a valid search continuation token.")
        try:
            encoded = cursor[3:]
            encoded += "=" * (-len(encoded) % 4)
            state = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise BridgeError("INVALID_INPUT: cursor is not a valid search continuation token.") from exc
        skip_remaining = state.get("skip", 0) if isinstance(state, dict) else None
        if (not isinstance(state, dict) or state.get("version") not in {1, 2} or
                type(state.get("file")) is not int or state["file"] < 0 or
                type(state.get("line")) is not int or state["line"] < 1 or
                type(skip_remaining) is not int or skip_remaining < 0):
            raise BridgeError("INVALID_INPUT: cursor is not a valid search continuation token.")
        return state["file"], state["line"], skip_remaining

    @staticmethod
    def _validate_search_pattern(pattern, regex):
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 500 or "\x00" in pattern or "\n" in pattern:
            raise BridgeError("INVALID_INPUT: each search pattern must be 1-500 characters without NUL/newline.")
        if not regex:
            return re.escape(pattern)

        # ponytail: regex-lite whitelist avoids Python re backtracking; add a
        # bounded regex engine only if richer model-supplied expressions are required.
        in_class = False
        escaped = False
        for character in pattern:
            if escaped:
                if character.isdigit():
                    raise BridgeError("INVALID_INPUT: regex backreferences are not supported.")
                escaped = False
                continue
            if character == "\\":
                escaped = True
                continue
            if in_class:
                if character == "]":
                    in_class = False
                continue
            if character == "[":
                in_class = True
            elif character == "]" or character in "()|*+?{}":
                raise BridgeError(
                    "INVALID_INPUT: regex uses an unsafe backtracking construct; "
                    "use literals, character classes, anchors, or separate patterns."
                )
        if escaped or in_class:
            raise BridgeError("INVALID_INPUT: regex contains an incomplete escape or character class.")
        return pattern

    def _search_code(self, patterns, prefix="", file_types=None, case_sensitive=True,
                     max_results=50, cursor=0, context_lines=2, regex=False,
                     include_globs=None, exclude_globs=None, include_patterns=False):
        integer(max_results, "max_results", 1, 100)
        resume_file = resume_line = 0
        skip_remaining = 0
        if isinstance(cursor, str):
            resume_file, resume_line, skip_remaining = self._search_cursor_decode(cursor)
        else:
            integer(cursor, "cursor", 0, 100000)
            skip_remaining = cursor
        integer(context_lines, "context_lines", 0, 5)
        if type(case_sensitive) is not bool:
            raise BridgeError("INVALID_INPUT: case_sensitive must be boolean.")
        if not isinstance(patterns, list) or not 1 <= len(patterns) <= _SEARCH_MAX_PATTERNS:
            raise BridgeError(f"INVALID_INPUT: patterns must contain 1-{_SEARCH_MAX_PATTERNS} items.")
        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(self._validate_search_pattern(pattern, regex), flags))
            except re.error as exc:
                raise BridgeError("INVALID_INPUT: patterns must be valid regular expressions.") from exc
        if exclude_globs is None:
            exclude_globs = _SEARCH_DEFAULT_EXCLUDES
        deadline = time.monotonic() + _SEARCH_TIME_BUDGET_SECONDS
        results, scanned, more, timed_out = [], 0, False, False
        resume_at_file, resume_at_line = resume_file, resume_line or 1
        for file_index, relative in enumerate(self._search_candidates(prefix, file_types, include_globs, exclude_globs)):
            if file_index < resume_file:
                continue
            line_start = resume_at_line if file_index == resume_file else 1
            if time.monotonic() >= deadline:
                timed_out = True
                resume_at_file, resume_at_line = file_index, line_start
                break
            scanned += 1
            try:
                _, path, data = self._read_bytes(relative)
                text = data.decode("utf-8")
            except (BridgeError, UnicodeDecodeError):
                resume_at_file, resume_at_line = file_index + 1, 1
                continue
            if "\x00" in text:
                resume_at_file, resume_at_line = file_index + 1, 1
                continue
            lines = text.splitlines()
            for number, actual in enumerate(lines, 1):
                if number < line_start:
                    continue
                if time.monotonic() >= deadline:
                    timed_out = True
                    resume_at_file, resume_at_line = file_index, number
                    break
                hit_patterns = [pattern for pattern, compiled_pattern in zip(patterns, compiled)
                                if compiled_pattern.search(actual)]
                expired = time.monotonic() >= deadline
                if not hit_patterns:
                    resume_at_file, resume_at_line = file_index, number + 1
                    if expired:
                        timed_out = True
                        break
                    continue
                if skip_remaining:
                    skip_remaining -= 1
                    resume_at_file, resume_at_line = file_index, number + 1
                    if expired:
                        timed_out = True
                        break
                    continue
                if len(results) >= max_results:
                    more = True
                    resume_at_file, resume_at_line = file_index, number
                    break
                item = {"path": path, "line": number, "text": _redact(actual),
                        "context_start_line": max(1, number-context_lines),
                        "context": _redact("\n".join(lines[max(0, number-context_lines-1):number+context_lines])),
                        "sha256": _sha256(data)}
                if include_patterns:
                    item["patterns"] = hit_patterns
                results.append(item)
                resume_at_file, resume_at_line = file_index, number + 1
                if expired:
                    timed_out = True
                    break
            if more or timed_out:
                break
            resume_at_file, resume_at_line = file_index + 1, 1
        next_cursor = (self._search_cursor_encode(resume_at_file, resume_at_line, skip_remaining)
                       if timed_out or more else None)
        return {"matches": results, "next_cursor": next_cursor,
                "inventory_truncated": False, "output_truncated": False,
                "scanned_files": scanned, "scan_truncated": timed_out,
                "warnings": (["SEARCH_TIMEOUT: search_code/search_code_batch reached the 5-second budget; "
                               "use next_cursor or narrow the search scope."] if timed_out else []),
                "hint": ("Search time budget reached; retry with next_cursor or narrow prefix/include_globs."
                          if timed_out else
                          "Cursors apply to current file contents; use read_file for full evidence.")}

    def search_code_batch(self, patterns, prefix="", include_globs=None, exclude_globs=None,
                          case_sensitive=True, max_results=50, cursor=0, context_lines=2):
        return self._search_code(patterns, prefix, None, case_sensitive, max_results, cursor,
                                 context_lines, regex=True, include_globs=include_globs,
                                 exclude_globs=exclude_globs, include_patterns=True)

    def git_diff(self, raw_path=None):
        if not git_repository(self.root):
            raise BridgeError("NOT_A_REPOSITORY: per-change diffs still work for this folder.")
        exe = shutil.which("git")
        if not exe:
            raise BridgeError("UNSUPPORTED_CAPABILITY: Git is not installed.")
        inventory_truncated = False
        if raw_path:
            target, relative = self._file(raw_path, allow_missing=True)
            if target.exists():
                self._read_bytes(raw_path)
            paths = [relative]
        else:
            # Read index paths without opening sensitive working files to compare their contents.
            listing = self._command_read([exe, "--no-optional-locks", "-c", "core.fsmonitor=false", "ls-files", "--cached", "-z"])
            if listing.get("exitCode") != 0:
                raise BridgeError("DIFF_FAILED: Git could not list tracked paths.")
            inventory_truncated = len(listing.get("stdout", "").encode("utf-8")) >= 262144
            paths = []
            for raw in listing.get("stdout", "").split("\x00"):
                if not raw:
                    continue
                try:
                    target, relative = self._file(raw, allow_missing=True)
                    if target.exists():
                        self._read_bytes(raw)
                    paths.append(relative)
                except BridgeError:
                    continue
        chunks = []
        for offset in range(0,len(paths),40):
            args = [exe, "--no-optional-locks", "-c", "core.fsmonitor=false", "diff", "--no-ext-diff", "--no-textconv", "--unified=3", "--", *paths[offset:offset+40]]
            result = self._command_read(args)
            if result.get("exitCode") != 0:
                raise BridgeError("DIFF_FAILED: Git could not produce a protected diff.")
            chunk = result.get("stdout", "")
            if "\x00" in chunk or "\ufffd" in chunk:
                raise BridgeError("BINARY_BLOCKED: Git returned non-UTF-8 or binary diff content.")
            chunks.append(chunk)
        diff, truncated = _bounded("".join(chunks))
        return {"path": raw_path, "exit_code": 0, "diff": diff, "stderr": "", "truncated": truncated or inventory_truncated}

    def list_skills(self):
        response = self.runtime.call("skills/list", {"cwds": [str(self.root)], "forceReload": True})
        skills = {}
        for entry in response.get("data", []):
            if Path(entry.get("cwd", "")).resolve() != self.root:
                continue
            for skill in entry.get("skills", []):
                path = Path(skill.get("path", ""))
                if not path.is_absolute() or path.name != "SKILL.md" or not skill.get("enabled", True):
                    continue
                try:
                    check_link_chain(path)
                    if not path.is_file():
                        continue
                except BridgeError:
                    continue
                key = _sha256(str(path).encode())[:20]
                skills[key] = {"skill_id": key, "name": skill.get("name", path.parent.name),
                               "description": _redact(skill.get("description", ""))[:1000], "path": path}
        self.skills = skills
        return {"skills": [{k:v for k,v in skill.items() if k != "path"} for skill in skills.values()],
                "instruction": "Skills are guidance only. They never authorize script execution or new tools."}

    def _skill_read(self, skill_id, path, start_line, max_bytes):
        if skill_id not in self.skills:
            raise BridgeError("SCOPE_DENIED: call list_skills before reading a discovered skill.")
        root = self.skills[skill_id]["path"].parent
        files = ProjectFiles(BridgeConfig(root, {}, max_file_bytes=self.config.max_file_bytes))
        return files.read_file(path, start_line, max_bytes)

    def read_skill(self, skill_id, start_line=1, max_bytes=20000):
        return self._skill_read(skill_id, "SKILL.md", start_line, max_bytes)

    def read_skill_resource(self, skill_id, path, start_line=1, max_bytes=20000):
        return self._skill_read(skill_id, path, start_line, max_bytes)

    def list_codex_threads(self, cursor=None, limit=20):
        integer(limit,"limit",1,50)
        if cursor not in self.thread_pages:
            raise BridgeError("SCOPE_DENIED: unknown project pagination cursor.")
        response = self.runtime.call("thread/list", {"cwd": str(self.root), "limit": limit, "cursor": cursor,
                                                      "useStateDbOnly": True})
        threads = []
        for entry in response.get("data", []):
            if Path(entry.get("cwd", "")).resolve() != self.root:
                continue
            self.known_threads.add(entry["id"])
            threads.append({"thread_id": entry["id"], "title": _redact(entry.get("name") or entry.get("preview", ""))[:300],
                            "updated_at": entry.get("updatedAt"), "status": entry.get("status")})
        next_cursor = response.get("nextCursor")
        self.thread_pages.add(next_cursor)
        return {"threads": threads, "next_cursor": next_cursor}

    def read_codex_thread(self, thread_id, start_turn=0, limit=5):
        integer(start_turn,"start_turn",0,100000)
        integer(limit,"limit",1,10)
        if thread_id not in self.known_threads:
            raise BridgeError("SCOPE_DENIED: first select a thread returned by list_codex_threads for this project.")
        meta = self.runtime.call("thread/read", {"threadId":thread_id,"includeTurns":False})["thread"]
        if Path(meta.get("cwd", "")).resolve() != self.root:
            raise BridgeError("SCOPE_DENIED: thread belongs to another project.")
        thread = self.runtime.call("thread/read", {"threadId":thread_id,"includeTurns":True})["thread"]
        if Path(thread.get("cwd", "")).resolve() != self.root:
            raise BridgeError("SCOPE_DENIED: thread project changed.")
        turns = []
        for turn in thread.get("turns", [])[start_turn:start_turn+limit]:
            messages = []
            for item in turn.get("items", []):
                if item.get("type") == "agentMessage":
                    messages.append({"role":"assistant", "text":_bounded(item.get("text", ""),8000)[0]})
                elif item.get("type") == "userMessage":
                    text = "\n".join(c.get("text", "") for c in item.get("content", []) if c.get("type") == "text")
                    messages.append({"role":"user", "text":_bounded(text,8000)[0]})
            turns.append({"turn_id":turn.get("id"), "status":turn.get("status"), "messages":messages})
        total = len(thread.get("turns", []))
        return {"thread_id":thread_id,"turns":turns,"next_turn":start_turn+limit if start_turn+limit<total else None,
                "note":"Conversation text only; commands, file snapshots and private tool output are omitted."}

    def _docs(self, tool, arguments):
        if tool not in {"search_openai_docs", "fetch_openai_doc"}:
            raise BridgeError("SCOPE_DENIED: only the two documentation tools are allowed.")
        with self.lock:
            if self.docs_thread is None:
                response = self.runtime.call("thread/start", {"cwd":str(self.root),"ephemeral":True,
                    "approvalPolicy":"never", "approvalsReviewer":"user", "permissions":"bridge",
                    "environments":[],
                    "baseInstructions":"Technical MCP documentation context only. No model turns.",
                    "config":{"project_doc_max_bytes":0,"mcp_servers":{"openaiDeveloperDocs":{"url":"https://developers.openai.com/mcp",
                                "enabled_tools":["search_openai_docs","fetch_openai_doc"]}}}}, timeout=45)
                self.docs_thread = response["thread"]["id"]
            return self.runtime.call("mcpServer/tool/call", {"threadId":self.docs_thread,
                "server":"openaiDeveloperDocs", "tool":tool, "arguments":arguments}, timeout=60)

    def codex_docs_search(self, query, limit=5, cursor=None):
        if not isinstance(query,str) or not 1 <= len(query) <= 500:
            raise BridgeError("INVALID_INPUT: query needs 1-500 characters.")
        integer(limit,"limit",1,10)
        args = {"query":query,"limit":limit}
        if cursor:
            if not isinstance(cursor,str) or len(cursor)>2000:
                raise BridgeError("INVALID_INPUT: invalid cursor.")
            args["cursor"] = cursor
        return {"result": self._docs("search_openai_docs",args)}

    def codex_docs_fetch(self, url, anchor=None):
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in {"developers.openai.com","platform.openai.com","learn.chatgpt.com"} or parsed.username or parsed.password or parsed.port not in (None,443):
            raise BridgeError("SCOPE_DENIED: only official OpenAI HTTPS documentation URLs are allowed.")
        args = {"url":url}
        if anchor:
            if not isinstance(anchor,str) or len(anchor)>200:
                raise BridgeError("INVALID_INPUT: invalid anchor.")
            args["anchor"] = anchor
        return {"result": self._docs("fetch_openai_doc",args)}

    def _init_security_journal(self):
        # Reuse ChangeJournal's WAL/lock: this is the durable bridge-journal
        # for Security request idempotency and checkpoints.
        with self.db:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS security_requests (
                    request_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    scan_id TEXT,
                    status TEXT NOT NULL,
                    review_mode TEXT,
                    target TEXT,
                    phase TEXT,
                    created REAL NOT NULL,
                    updated REAL NOT NULL
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS security_scans (
                    scan_id TEXT PRIMARY KEY,
                    review_mode TEXT,
                    target TEXT,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    last_request_id TEXT,
                    coverage_json TEXT,
                    finding_counts_json TEXT,
                    findings_json TEXT,
                    created REAL NOT NULL,
                    updated REAL NOT NULL
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS security_checkpoints (
                    scan_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created REAL NOT NULL,
                    PRIMARY KEY(scan_id, phase)
                )
            """)
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(security_requests)")}
            if "client_request_id" not in columns:
                self.db.execute("ALTER TABLE security_requests ADD COLUMN client_request_id TEXT")
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(security_scans)")}
            if "revision" not in columns:
                self.db.execute("ALTER TABLE security_scans ADD COLUMN revision INTEGER NOT NULL DEFAULT 0")
            if "last_request_id" not in columns:
                self.db.execute("ALTER TABLE security_scans ADD COLUMN last_request_id TEXT")
            for column in ("coverage_json", "finding_counts_json", "findings_json"):
                if column not in columns:
                    self.db.execute(f"ALTER TABLE security_scans ADD COLUMN {column} TEXT")
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS security_phase_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    request_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_hash TEXT,
                    created REAL NOT NULL
                )
            """)

    @staticmethod
    def _security_hash(value):
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise BridgeError("INVALID_INPUT: Security payload must be JSON data.") from exc
        if len(encoded) > 2 * 1024 * 1024:
            raise BridgeError("INVALID_INPUT: Security payload is too large.")
        return _sha256(encoded)

    def _security_operation_request_id(self, request_id, operation, scan_id, phase=None):
        """Scope new mutation keys so one model id can be retried per operation."""
        old = self._security_request_record(request_id)
        if old and old["operation"] == operation:
            return request_id
        scope = {"request_id": request_id, "operation": operation,
                 "scan_id": scan_id, "phase": phase}
        return "security-" + self._security_hash(scope)[:48]

    @staticmethod
    def _security_status_from_scan(scan, fallback="running"):
        if not isinstance(scan, dict):
            return fallback
        return _security_status(scan.get("status") or scan.get("state"), fallback)

    @staticmethod
    def _security_phase_from_scan(scan, fallback="preflight"):
        if not isinstance(scan, dict):
            return fallback
        return scan.get("currentPhase") or scan.get("current_phase") or scan.get("phase") or fallback

    @staticmethod
    def _security_scan_from_response(response):
        if not isinstance(response, dict):
            native = getattr(response, "native_result", None)
            response = native if isinstance(native, dict) else None
        if not isinstance(response, dict):
            raise BridgeError("SECURITY_ADAPTER_INVALID: adapter returned a non-object response.")
        pending, seen = [response], set()
        values = []
        while pending:
            value = pending.pop(0)
            if not isinstance(value, dict) or id(value) in seen:
                continue
            seen.add(id(value))
            values.append(value)
            for key in ("structuredContent", "result", "data", "workspace", "results", "scan", "state"):
                child = value.get(key)
                if isinstance(child, dict):
                    pending.append(child)
        for value in values:
            scan = value.get("scan")
            if isinstance(scan, dict):
                return scan
        for value in values:
            if any(key in value for key in ("status", "state", "phase", "currentPhase", "current_phase")):
                return value
        return response

    @staticmethod
    def _security_start_scan_id(response):
        if not isinstance(response, dict):
            native = getattr(response, "native_result", None)
            response = native if isinstance(native, dict) else None
        pending, seen = ([response] if isinstance(response, dict) else []), set()
        while pending:
            value = pending.pop(0)
            if not isinstance(value, dict) or id(value) in seen:
                continue
            seen.add(id(value))
            workspace = value.get("workspace")
            results = workspace.get("results") if isinstance(workspace, dict) else None
            scan_id = results.get("scanId") if isinstance(results, dict) else None
            if isinstance(scan_id, str):
                return _security_scan_key(scan_id)
            for key in ("structuredContent", "result", "data", "workspace"):
                child = value.get(key)
                if isinstance(child, dict):
                    pending.append(child)
        raise BridgeError("SECURITY_START_FAILED: adapter response has no workspace.results.scanId.")

    @staticmethod
    def _security_find_scan_id(response):
        if not isinstance(response, dict):
            return None
        try:
            return LocalBridge._security_start_scan_id(response)
        except BridgeError:
            scan_id = response.get("scanId") or response.get("scan_id")
            if isinstance(scan_id, str):
                try:
                    return _security_scan_key(scan_id)
                except BridgeError:
                    return None
        return None

    def _security_adapter_method(self, name, optional=False):
        if self.security_adapter is None and not optional:
            self._ensure_security_adapter()
        method = getattr(self.security_adapter, name, None) if self.security_adapter is not None else None
        if callable(method):
            return method
        if optional:
            return None
        raise BridgeError("SECURITY_ADAPTER_UNAVAILABLE: direct Security adapter is not configured.")

    def _ensure_security_adapter(self):
        if self.security_adapter is not None:
            return self.security_adapter
        try:
            from security_mcp import SecurityMcpAdapter
            self.security_adapter = SecurityMcpAdapter(self.state, self.root).start()
        except Exception as exc:
            raise BridgeError("SECURITY_ADAPTER_UNAVAILABLE: direct Security MCP is not ready.") from exc
        return self.security_adapter

    def _security_call(self, name, *args):
        method = self._security_adapter_method(name)
        try:
            return method(*args)
        except SecurityMcpTimeout as exc:
            raise BridgeError(
                "SECURITY_RUNTIME_TIMEOUT: native Security result is unknown; "
                "retry the same request_id or read security_get_scan."
            ) from exc
        except SecurityMcpIdempotencyConflict as exc:
            raise BridgeError(
                "IDEMPOTENCY_CONFLICT: Security request_id is already bound to a different payload."
            ) from exc
        except BridgeError:
            raise
        except Exception as exc:
            # Adapter internals can contain paths/tokens; never reflect them.
            raise BridgeError("SECURITY_ADAPTER_FAILED: direct Security operation failed.") from exc

    def _security_optional_call(self, name, *args):
        method = self._security_adapter_method(name, optional=True)
        if method is None:
            return None
        try:
            return method(*args)
        except BridgeError:
            raise
        except Exception as exc:
            raise BridgeError("SECURITY_ADAPTER_FAILED: direct Security operation failed.") from exc

    def _security_validate_start(self, review_mode, target, user_context, request_id):
        if review_mode not in _SECURITY_MODES:
            raise BridgeError("INVALID_INPUT: review_mode must be standard or chatgpt_deep.")
        if target not in _SECURITY_TARGETS:
            raise BridgeError("INVALID_INPUT: target must be codebase or changes.")
        if target == "changes" and not git_repository(self.root):
            raise BridgeError("UNSUPPORTED_TARGET: changes requires a Git repository.")
        if user_context is not None and (not isinstance(user_context, str) or len(user_context) > 4000 or "\x00" in user_context):
            raise BridgeError("INVALID_INPUT: user_context must be at most 4000 characters without NUL bytes.")
        request_key(request_id)
        return user_context

    @staticmethod
    def _security_native_target(target):
        return {"kind": "working_tree"} if target == "changes" else {"kind": "codebase"}

    @staticmethod
    def _security_sequence(review_mode):
        if review_mode == "standard":
            return _SECURITY_STANDARD_PHASES
        if review_mode == "chatgpt_deep":
            return _SECURITY_DEEP_PHASES
        raise BridgeError("SECURITY_STATE_INVALID: unknown review mode.")

    @classmethod
    def _security_next_phase(cls, review_mode, phase):
        phases = cls._security_sequence(review_mode)
        if phase == "complete":
            return None
        try:
            index = phases.index(phase)
        except ValueError as exc:
            raise BridgeError("SECURITY_STATE_INVALID: unknown workflow phase.") from exc
        return phases[index + 1] if index + 1 < len(phases) else "complete"

    def _security_public_value(self, value, key=""):
        if isinstance(value, dict):
            safe = {}
            for raw_key, raw_value in value.items():
                name = str(raw_key)
                lowered = name.casefold().replace("-", "_")
                if (lowered in _SECURITY_SENSITIVE_KEYS or "token" in lowered or "secret" in lowered or
                        "password" in lowered or "credential" in lowered or "path" in lowered or
                        lowered in {"cwd", "directory", "dir"}):
                    continue
                safe[name] = self._security_public_value(raw_value, name)
            return safe
        if isinstance(value, list):
            return [self._security_public_value(item, key) for item in value[:200]]
        if isinstance(value, tuple):
            return [self._security_public_value(item, key) for item in value[:200]]
        if isinstance(value, str):
            return _security_redact_text(value)[:20000]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return _security_redact_text(value)[:20000]

    def _security_scan_record(self, scan_id):
        return self.db.execute("SELECT * FROM security_scans WHERE scan_id=?", (scan_id,)).fetchone()

    def _security_request_record(self, request_id):
        return self.db.execute("SELECT * FROM security_requests WHERE request_id=?", (request_id,)).fetchone()

    def _security_checkpoint_record(self, scan_id, phase):
        return self.db.execute(
            "SELECT * FROM security_checkpoints WHERE scan_id=? AND phase=?",
            (scan_id, phase),
        ).fetchone()

    def _security_start_record_for_scan(self, scan_id):
        return self.db.execute(
            "SELECT * FROM security_requests WHERE operation='start' AND scan_id=? ORDER BY created LIMIT 1",
            (scan_id,)).fetchone()

    @staticmethod
    def _security_json(value):
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise BridgeError("SECURITY_STATE_INVALID: Security aggregate is not JSON data.") from exc

    def _security_save_scan(self, scan_id, review_mode, target, status, phase, request_id=None,
                            force_revision=False, coverage=None, finding_counts=None, findings=None,
                            commit=True):
        now = time.time()
        status = _security_status(status)
        if not isinstance(phase, str) or not phase:
            phase = "complete" if status == "completed" else "preflight"
        coverage_json = self._security_json(coverage) if coverage is not None else None
        finding_counts_json = self._security_json(finding_counts) if finding_counts is not None else None
        findings_json = self._security_json(findings) if findings is not None else None
        with (self.db if commit else nullcontext()):
            old = self._security_scan_record(scan_id)
            if old:
                review_mode = review_mode or old["review_mode"]
                target = target or old["target"]
                changed = (force_revision or review_mode != old["review_mode"] or target != old["target"] or
                           status != old["status"] or phase != old["phase"])
                revision = int(old["revision"] or 0) + (1 if changed else 0)
                self.db.execute("""UPDATE security_scans
                    SET review_mode=?, target=?, status=?, phase=?, revision=?,
                        last_request_id=COALESCE(?,last_request_id),
                        coverage_json=COALESCE(?,coverage_json),
                        finding_counts_json=COALESCE(?,finding_counts_json),
                        findings_json=COALESCE(?,findings_json), updated=? WHERE scan_id=?""",
                    (review_mode, target, status, phase, revision, request_id, coverage_json,
                     finding_counts_json, findings_json, now, scan_id))
            else:
                revision = 1
                self.db.execute("""INSERT INTO security_scans
                    (scan_id,review_mode,target,status,phase,revision,last_request_id,
                     coverage_json,finding_counts_json,findings_json,created,updated)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, review_mode, target, status, phase, revision, request_id,
                     coverage_json, finding_counts_json, findings_json, now, now))
            self.db.execute("""UPDATE security_requests
                SET scan_id=COALESCE(?,scan_id), status=?, phase=?, updated=?
                WHERE operation='start' AND scan_id=?""", (scan_id, status, phase, now, scan_id))
            return revision

    def _security_finish_request(self, request_id, status, scan_id=None, phase=None, commit=True):
        with (self.db if commit else nullcontext()):
            self.db.execute("""UPDATE security_requests
                SET scan_id=COALESCE(?,scan_id), status=?, phase=COALESCE(?,phase), updated=?
                WHERE request_id=?""", (scan_id, status, phase, time.time(), request_id))

    def _security_save_checkpoint(self, scan_id, phase, request_id, payload_hash, commit=True):
        with (self.db if commit else nullcontext()):
            self.db.execute(
                "INSERT OR REPLACE INTO security_checkpoints"
                "(scan_id,phase,request_id,payload_hash,created) VALUES (?,?,?,?,?)",
                (scan_id, phase, request_id, payload_hash, time.time()),
            )

    def _security_phase_audit(self, scan_id, phase, revision, request_id, status, payload_hash, commit=True):
        with (self.db if commit else nullcontext()):
            self.db.execute(
                "INSERT INTO security_phase_audit"
                "(scan_id,phase,revision,request_id,status,payload_hash,created) VALUES (?,?,?,?,?,?,?)",
                (scan_id, phase, revision, request_id, status, payload_hash, time.time()),
            )

    @staticmethod
    def _security_json_value(row, column):
        if not row or column not in row.keys() or row[column] is None:
            return None
        try:
            return json.loads(row[column])
        except (TypeError, ValueError) as exc:
            raise BridgeError("SECURITY_STATE_INVALID: persisted Security aggregate is invalid.") from exc

    @staticmethod
    def _security_finding_counts(findings):
        if not isinstance(findings, list):
            return None
        by_severity = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = finding.get("severity")
            if isinstance(severity, dict):
                severity = severity.get("level")
            severity = str(severity).casefold() if severity else "unknown"
            by_severity[severity] = by_severity.get(severity, 0) + 1
        return {"total": len(findings), "bySeverity": by_severity}

    def _security_view(self, scan_id, raw_scan=None, fallback=None):
        scan = self._security_scan_from_response(raw_scan or {})
        fallback = fallback or self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
        status = self._security_status_from_scan(scan, fallback["status"] if fallback else "running")
        review_mode = (scan.get("reviewMode") or scan.get("review_mode") if isinstance(scan, dict) else None)
        target = scan.get("target") if isinstance(scan, dict) else None
        if fallback:
            review_mode = review_mode or fallback["review_mode"]
            target = target or fallback["target"]
        if review_mode not in _SECURITY_MODES:
            review_mode = None
        if target not in _SECURITY_TARGETS:
            target = None
        phase = self._security_phase_from_scan(scan, fallback["phase"] if fallback else "preflight")
        if status == "completed":
            phase = "complete"
        elif not isinstance(phase, str):
            raise BridgeError("SECURITY_STATE_INVALID: adapter returned an invalid phase.")
        result = {
            "scanId": scan_id,
            "reviewMode": review_mode,
            "target": target,
            "status": status,
            "phase": phase,
            "currentPhase": phase,
            "nextPhase": None if status in _SECURITY_TERMINAL else self._security_next_phase(review_mode, phase),
            "updatedAt": (scan.get("updatedAt") or scan.get("updated_at")
                          if isinstance(scan, dict) else None) or datetime_now(),
            "revision": int(fallback["revision"] or 0) if fallback and "revision" in fallback.keys() else 0,
            "stateSource": "bridge_journal",
        }
        coverage = scan.get("coverageSoFar", scan.get("coverage_so_far", scan.get("coverage"))) if isinstance(scan, dict) else None
        counts = scan.get("findingCounts", scan.get("finding_counts")) if isinstance(scan, dict) else None
        if coverage is None:
            coverage = self._security_json_value(fallback, "coverage_json")
        if counts is None:
            counts = self._security_json_value(fallback, "finding_counts_json")
        if coverage is not None:
            result["coverageSoFar"] = self._security_public_value(coverage)
        if isinstance(counts, dict):
            result["findingCounts"] = self._security_public_value(counts)
        result["phaseInstructions"] = self._security_phase_instructions(phase)
        history = self.db.execute(
            "SELECT phase,revision,request_id,status,created FROM security_phase_audit "
            "WHERE scan_id=? ORDER BY revision,created", (scan_id,)
        ).fetchall()
        result["phaseHistory"] = [{
            "phase": row["phase"], "revision": row["revision"], "requestId": row["request_id"],
            "status": row["status"], "committedAt": datetime.fromtimestamp(
                row["created"], timezone.utc
            ).isoformat().replace("+00:00", "Z")
        } for row in history]
        latest = result["phaseHistory"][-1] if result["phaseHistory"] else None
        result["committedPhase"] = latest["phase"] if latest else None
        result["committedAt"] = latest["committedAt"] if latest else None
        recovery = self.db.execute(
            "SELECT operation,status,request_id,client_request_id FROM security_requests "
            "WHERE scan_id=? AND status IN ('pending','uncertain') ORDER BY updated DESC LIMIT 1", (scan_id,)
        ).fetchone()
        result["recoveryRequired"] = recovery is not None
        result["recoveryRequestId"] = (recovery["client_request_id"] or recovery["request_id"] if recovery else None)
        result["recoveryOperation"] = recovery["operation"] if recovery else None
        result["recoveryStatus"] = recovery["status"] if recovery else None
        return result

    @staticmethod
    def _security_phase_instructions(phase):
        instructions = {
            "preflight": "Confirm the fixed project and review scope, then commit preflight.",
            "inventory": "Inventory entry points and security boundaries, then commit inventory.",
            "threat_model": "Record source-backed trust boundaries and threats, then commit the threat model.",
            "discovery": "Run one source-backed discovery pass and commit candidates plus coverage.",
            "attack_surface": "Review attack surface, entry points and trust boundaries, then commit candidates.",
            "auth_data_flow": "Review auth, authorization, secrets and data flow, then commit candidates.",
            "injection_file_process_network_state": "Review injection, file, process, network, unsafe execution and state handling, then commit candidates.",
            "deduplicate": "Deduplicate and merge candidates before validation, then commit the result.",
            "validation": "Validate candidates against source evidence, then commit validations.",
            "attack_path": "Analyze attack paths for validated findings, then commit attack paths.",
            "finalization": "Record final findings and coverage, then complete the scan.",
            "complete": "The scan is complete.",
        }
        return instructions.get(phase, "Follow the returned workflow phase and commit its checkpoint.")

    def _security_authoritative(self, scan_id, fallback=None, advance=False):
        if advance:
            method = self._security_adapter_method("continue_scan", optional=True)
            raw = self._security_call("continue_scan", scan_id) if method else self._security_call("get_scan", scan_id)
        else:
            raw = self._security_call("get_scan", scan_id)
        scan = self._security_scan_from_response(raw)
        view = self._security_view(scan_id, scan, fallback)
        self._security_save_scan(scan_id, view["reviewMode"], view["target"], view["status"], view["phase"])
        return view, scan

    def _security_active_scan(self):
        rows = self.db.execute("SELECT * FROM security_scans ORDER BY created DESC").fetchall()
        for row in rows:
            if row["status"] in _SECURITY_TERMINAL:
                continue
            # Recovery reads the bridge journal only; a native call here would
            # make a timed-out Security mutation block every later request.
            return row
        pending_start = self.db.execute(
            "SELECT * FROM security_requests WHERE operation='start' "
            "AND status IN ('pending','uncertain') ORDER BY created DESC LIMIT 1"
        ).fetchone()
        if pending_start:
            return pending_start
        return None

    def _security_check_request(self, request_id, operation, payload_hash, scan_id=None):
        old = self._security_request_record(request_id)
        if not old:
            return None
        if old["operation"] != operation or old["payload_hash"] != payload_hash or (
                scan_id is not None and old["scan_id"] not in (None, scan_id)):
            raise BridgeError("IDEMPOTENCY_CONFLICT: request_id already describes another Security operation.")
        return old

    def _security_insert_request(self, request_id, operation, payload_hash, scan_id=None,
                                 status="pending", review_mode=None, target=None, phase=None,
                                 client_request_id=None):
        now = time.time()
        with self.db:
            self.db.execute("""INSERT INTO security_requests
                (request_id,operation,payload_hash,scan_id,status,review_mode,target,phase,created,updated,client_request_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (request_id, operation, payload_hash, scan_id, status, review_mode, target, phase, now, now,
                 client_request_id))

    def _security_mutation_payload(self, operation, scan_id, phase=None, phase_data=None):
        return {"operation": operation, "scan_id": scan_id, "phase": phase, "phase_data": phase_data}

    def _security_phase_payload(self, phase, phase_data, fields):
        if phase_data is None:
            phase_data = {}
        if not isinstance(phase_data, dict):
            raise BridgeError("INVALID_INPUT: phase data must be an object.")
        data = dict(phase_data)
        aliases = {"threat_model": "threatModel", "attack_paths": "attackPaths",
                   "candidate_validations": "validations"}
        for key, value in fields.items():
            mapped = aliases.get(key, key)
            if mapped in data:
                raise BridgeError("INVALID_INPUT: duplicate phase field.")
            data[mapped] = value
        if "payload" in data:
            raise BridgeError("INVALID_INPUT: phase-specific fields are required; payload is not accepted.")
        allowed = _SECURITY_PHASE_FIELDS.get(phase)
        if allowed is None:
            raise BridgeError("INVALID_INPUT: unknown workflow phase.")
        unknown = set(data) - allowed
        if unknown:
            raise BridgeError("INVALID_INPUT: phase fields do not match the current workflow phase.")
        self._security_hash(data)
        return data

    def security_start_scan(self, review_mode, target, user_context=None, request_id=None):
        user_context = self._security_validate_start(review_mode, target, user_context, request_id)
        payload = {"review_mode": review_mode, "target": target, "user_context": user_context}
        payload_hash = self._security_hash(payload)
        native_mode = "diff" if target == "changes" else "standard"
        native_target = self._security_native_target(target)
        with self.lock:
            old = self._security_check_request(request_id, "start", payload_hash)
            if old:
                if old["scan_id"]:
                    view, _ = self._security_authoritative(old["scan_id"], old)
                    return {key: view[key] for key in
                            ("scanId", "reviewMode", "target", "status", "phase", "nextPhase", "updatedAt")}
                found = self._security_optional_call("find_scan_by_request", request_id, payload_hash)
                scan_id = self._security_find_scan_id(found)
                if not scan_id:
                    # A pending row means the previous process may have died
                    # between the adapter side effect and our journal commit.
                    # Retry the exact request; the direct adapter owns the
                    # native idempotency journal and must replay its scan.
                    response = self._security_call(
                        "start_scan", native_mode, native_target, user_context, request_id)
                    scan_id = self._security_start_scan_id(response)
                self._security_save_scan(scan_id, review_mode, target, "running", "preflight")
                self._security_finish_request(request_id, "running", scan_id, "preflight")
                view, _ = self._security_authoritative(scan_id, self._security_scan_record(scan_id))
                return {key: view[key] for key in
                        ("scanId", "reviewMode", "target", "status", "phase", "nextPhase", "updatedAt")}

            active = self._security_active_scan()
            if active:
                raise BridgeError("SECURITY_SCAN_ACTIVE: continue the active scan before creating another scan.")
            self._security_insert_request(request_id, "start", payload_hash, status="pending",
                                          review_mode=review_mode, target=target, phase="preflight")
            # No model/reasoning argument is intentionally present here.
            response = self._security_call("start_scan", native_mode, native_target, user_context, request_id)
            scan_id = self._security_start_scan_id(response)
            self._security_save_scan(scan_id, review_mode, target, "running", "preflight")
            self._security_finish_request(request_id, "running", scan_id, "preflight")
            return {
                "scanId": scan_id,
                "reviewMode": review_mode,
                "target": target,
                "status": "running",
                "phase": "preflight",
                "nextPhase": "inventory",
                "updatedAt": datetime_now(),
            }

    def security_get_scan(self, scan_id=None, request_id=None):
        if (scan_id is None) == (request_id is None):
            raise BridgeError("INVALID_INPUT: provide exactly one of scan_id or request_id.")
        with self.lock:
            if request_id is not None:
                request_key(request_id)
                request = self._security_request_record(request_id)
                if not request or request["operation"] != "start":
                    raise BridgeError("SECURITY_REQUEST_NOT_FOUND: widget start request is unknown.")
                scan_id = request["scan_id"]
                if not scan_id:
                    return {
                        "requestId": request_id,
                        "status": "pending",
                        "phase": "preflight",
                        "currentPhase": "preflight",
                        "nextPhase": "preflight",
                        "phaseInstructions": (
                            "The widget is still creating the scan. Retry security_get_scan with the same request_id; "
                            "do not call security_start_scan."
                        ),
                    }
            scan_id = _security_scan_key(scan_id)
            fallback = self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
            if not fallback:
                raise BridgeError("NOT_FOUND: unknown security scan.")
            view = self._security_view(scan_id, {}, fallback)
            if request_id is not None:
                view["requestId"] = request_id
            return view

    def security_task_snapshot(self, scan_id):
        scan_id = _security_scan_key(scan_id)
        with self.lock:
            row = self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
            if not row:
                raise BridgeError("NOT_FOUND: unknown security scan.")
            view = self._security_view(scan_id, {}, row)
            return view, row["created"], row["updated"]

    def security_continue_scan(self, scan_id):
        scan_id = _security_scan_key(scan_id)
        with self.lock:
            fallback = self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
            if not fallback:
                raise BridgeError("NOT_FOUND: unknown security scan.")
            return self._security_view(scan_id, {}, fallback)

    def security_commit_phase(self, scan_id, phase, phase_data=None, request_id=None, **fields):
        scan_id = _security_scan_key(scan_id)
        if request_id is None and isinstance(phase_data, str):
            request_id, phase_data = phase_data, None
        request_key(request_id)
        if not isinstance(phase, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,79}", phase):
            raise BridgeError("INVALID_INPUT: invalid workflow phase.")
        data = self._security_phase_payload(phase, phase_data, fields)
        payload_hash = self._security_hash(self._security_mutation_payload("commit", scan_id, phase, data))
        client_request_id = request_id
        with self.lock:
            request_id = self._security_operation_request_id(request_id, "commit", scan_id, phase)
            old = self._security_check_request(request_id, "commit", payload_hash, scan_id)
            if old and old["status"] == "done":
                return self.security_get_scan(scan_id)
            fallback = self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
            if not fallback:
                raise BridgeError("NOT_FOUND: unknown security scan.")
            current = self._security_view(scan_id, {}, fallback)
            checkpoint = self._security_checkpoint_record(scan_id, phase)
            if old and checkpoint and checkpoint["payload_hash"] == payload_hash:
                self._security_finish_request(request_id, "done", scan_id, current["phase"])
                return current
            if old and current["status"] in _SECURITY_TERMINAL:
                raise BridgeError("SECURITY_TERMINAL: scan is terminal; no mutation is allowed.")
            if old and current["phase"] != phase:
                expected = self._security_next_phase(current["reviewMode"], phase)
                if current["phase"] == expected:
                    self._security_finish_request(request_id, "done", scan_id, current["phase"])
                    return current
                raise BridgeError("SECURITY_PHASE_ORDER: pending checkpoint did not complete at the expected phase.")
            if current["status"] in _SECURITY_TERMINAL:
                raise BridgeError("SECURITY_TERMINAL: scan is terminal; no mutation is allowed.")
            if current["reviewMode"] not in _SECURITY_MODES:
                raise BridgeError("SECURITY_STATE_INVALID: scan has no supported review mode.")
            if current["phase"] != phase:
                raise BridgeError("SECURITY_PHASE_ORDER: phase does not match the authoritative current phase.")
            if phase == "finalization":
                if self._security_checkpoint_record(scan_id, phase) and not old:
                    raise BridgeError("SECURITY_FINALIZATION_ALREADY_COMMITTED: finalization is immutable.")
                findings = data.get("findings")
                if not isinstance(findings, list):
                    raise BridgeError(
                        "SECURITY_FINALIZATION_INVALID: findings must be a list; an empty list is valid."
                    )
            next_phase = self._security_next_phase(current["reviewMode"], phase)
            if not old:
                self._security_insert_request(request_id, "commit", payload_hash, scan_id, phase=phase,
                                              client_request_id=client_request_id)

        # Never hold the bridge operation lock while a native Security call is
        # in flight. A timeout leaves the result unknown, but recovery reads
        # and retries must still be available immediately.
        try:
            response = self._security_call("commit_phase", scan_id, phase, data, request_id)
            returned = self._security_scan_from_response(response or {})
            returned_phase = self._security_phase_from_scan(returned, next_phase)
            if returned_phase not in {phase, next_phase}:
                raise BridgeError("SECURITY_PHASE_ORDER: adapter advanced to an unexpected phase.")
            status = self._security_status_from_scan(returned, current["status"])
            coverage = returned.get("coverageSoFar", returned.get("coverage_so_far", returned.get("coverage")))
            coverage = coverage if coverage else data.get("coverage")
            finding_counts = returned.get("findingCounts", returned.get("finding_counts"))
            cached_findings = None
            if phase == "finalization":
                final_findings = data.get("findings")
                # Persist the complete sanitized set; list_findings applies the
                # caller's page limit when it reads this authoritative cache.
                cached_findings = self._security_public_findings(final_findings)
                if not isinstance(finding_counts, dict) or not finding_counts:
                    finding_counts = self._security_finding_counts(final_findings)
        except BridgeError:
            with self.lock:
                self._security_finish_request(request_id, "uncertain", scan_id, current["phase"])
            raise

        checkpoint_phase = phase if next_phase == "complete" else next_phase
        with self.lock:
            with self.db:
                revision = self._security_save_scan(
                    scan_id, current["reviewMode"], current["target"], status, checkpoint_phase,
                    request_id=request_id, force_revision=True, coverage=coverage,
                    finding_counts=finding_counts, findings=cached_findings, commit=False
                )
                self._security_save_checkpoint(scan_id, phase, request_id, payload_hash, commit=False)
                self._security_phase_audit(
                    scan_id, phase, revision, client_request_id, "committed", payload_hash, commit=False
                )
                self._security_finish_request(request_id, "done", scan_id, checkpoint_phase, commit=False)
            return self._security_view(scan_id, {"status": status, "phase": checkpoint_phase},
                                       self._security_scan_record(scan_id))

    def security_complete_scan(self, scan_id, request_id):
        scan_id = _security_scan_key(scan_id)
        request_key(request_id)
        payload_hash = self._security_hash(self._security_mutation_payload("complete", scan_id))
        client_request_id = request_id
        with self.lock:
            request_id = self._security_operation_request_id(request_id, "complete", scan_id)
            old = self._security_check_request(request_id, "complete", payload_hash, scan_id)
            fallback = self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
            if not fallback:
                raise BridgeError("NOT_FOUND: unknown security scan.")
            current = self._security_view(scan_id, {}, fallback)
            if old and old["status"] == "done":
                return current
            if old and current["status"] == "completed":
                self._security_finish_request(request_id, "done", scan_id, "complete")
                return current
            if current["status"] in _SECURITY_TERMINAL:
                raise BridgeError("SECURITY_TERMINAL: scan is terminal; no mutation is allowed.")
            if current["phase"] != "finalization":
                raise BridgeError("SECURITY_PHASE_ORDER: complete requires the finalization checkpoint.")
            if not self._security_checkpoint_record(scan_id, "finalization"):
                raise BridgeError("SECURITY_FINALIZATION_REQUIRED: finalization was not accepted.")
            if not old:
                self._security_insert_request(request_id, "complete", payload_hash, scan_id,
                                              phase="finalization", client_request_id=client_request_id)

        try:
            response = self._security_call("complete_scan", scan_id, request_id)
            returned = self._security_scan_from_response(response or {})
            status = self._security_status_from_scan(returned, "completed")
            if status not in {"completed", "failed"}:
                raise BridgeError("SECURITY_COMPLETE_FAILED: adapter did not return a terminal result.")
        except BridgeError:
            with self.lock:
                self._security_finish_request(request_id, "uncertain", scan_id, current["phase"])
            raise

        phase = "complete" if status == "completed" else "finalization"
        with self.lock:
            self._security_save_scan(scan_id, current["reviewMode"], current["target"], status, phase,
                                     request_id=request_id)
            self._security_finish_request(request_id, "done", scan_id, phase)
            return self._security_view(scan_id, {"status": status, "phase": phase},
                                       self._security_scan_record(scan_id))

    def security_cancel_scan(self, scan_id, request_id):
        scan_id = _security_scan_key(scan_id)
        request_key(request_id)
        payload_hash = self._security_hash(self._security_mutation_payload("cancel", scan_id))
        with self.lock:
            request_id = self._security_operation_request_id(request_id, "cancel", scan_id)
            old = self._security_check_request(request_id, "cancel", payload_hash, scan_id)
            fallback = self._security_scan_record(scan_id) or self._security_start_record_for_scan(scan_id)
            current, _ = self._security_authoritative(scan_id, fallback)
            if old and old["status"] == "done":
                return current
            if old and current["status"] == "cancelled":
                self._security_finish_request(request_id, "done", scan_id, current["phase"])
                return current
            if current["status"] in _SECURITY_TERMINAL:
                raise BridgeError("SECURITY_TERMINAL: scan is terminal; no mutation is allowed.")
            if not old:
                self._security_insert_request(request_id, "cancel", payload_hash, scan_id, phase=current["phase"])
            response = self._security_call("cancel_scan", scan_id, request_id)
            returned = self._security_scan_from_response(response or {})
            status = self._security_status_from_scan(returned, "cancelled")
            if status != "cancelled":
                raise BridgeError("SECURITY_CANCEL_FAILED: adapter did not confirm cancellation.")
            phase = self._security_phase_from_scan(returned, current["phase"])
            self._security_save_scan(scan_id, current["reviewMode"], current["target"], status, phase)
            self._security_finish_request(request_id, "done", scan_id, phase)
            return self._security_view(scan_id, {"status": status, "phase": phase},
                                       self._security_scan_record(scan_id))

    def _security_public_file(self, value):
        if not isinstance(value, str) or not value:
            return None
        normalized = value.replace("\\", "/")
        if re.match(r"^(?:[A-Za-z]:/|/|//)", normalized):
            try:
                candidate = Path(value).resolve()
                relative = candidate.relative_to(self.root)
                normalized = relative.as_posix()
            except (OSError, ValueError):
                return None
        if any(part in {"", ".", ".."} for part in normalized.split("/")):
            return None
        # It is already a validated project-relative path; redacting the slash
        # here would turn a safe file name into unusable evidence.
        return normalized[:1000]

    def _security_public_findings(self, findings, max_items=None):
        if not isinstance(findings, list):
            return []
        result = []
        source = findings if max_items is None else findings[:max_items]
        for finding in source:
            if not isinstance(finding, dict):
                continue
            item = {}
            identifier = finding.get("id") or finding.get("findingId") or finding.get("occurrenceId")
            if identifier:
                item["id"] = self._security_public_value(identifier)
            for key in ("title", "description", "status", "rule", "owasp", "remediation"):
                if key in finding:
                    item[key] = self._security_public_value(finding[key], key)
            if "description" not in item:
                summary = finding.get("summary")
                if summary:
                    item["description"] = self._security_public_value(summary)

            severity = finding.get("severity")
            if isinstance(severity, dict):
                severity = severity.get("level")
            if severity:
                item["severity"] = self._security_public_value(str(severity).casefold())
            confidence = finding.get("confidence")
            if isinstance(confidence, dict):
                confidence = confidence.get("level")
            if confidence:
                item["confidence"] = self._security_public_value(str(confidence).casefold())
            rule_id = finding.get("ruleId")
            if rule_id and "rule" not in item:
                item["rule"] = self._security_public_value(rule_id)
            taxonomy = finding.get("taxonomy")
            if isinstance(taxonomy, dict) and taxonomy.get("cwe"):
                item["cwe"] = self._security_public_value(taxonomy["cwe"])

            locations = finding.get("locations")
            public_locations = []
            if isinstance(locations, list):
                for raw_location in locations[:50]:
                    if not isinstance(raw_location, dict):
                        continue
                    location_file = self._security_public_file(raw_location.get("path") or raw_location.get("file"))
                    if not location_file:
                        continue
                    public_location = {"file": location_file}
                    start = raw_location.get("startLine") or raw_location.get("start_line") or raw_location.get("line")
                    end = raw_location.get("endLine") or raw_location.get("end_line")
                    if isinstance(start, int) and not isinstance(start, bool) and start > 0:
                        public_location["startLine"] = start
                        if isinstance(end, int) and not isinstance(end, bool) and end >= start:
                            public_location["endLine"] = end
                    public_locations.append(public_location)
            if public_locations:
                item["locations"] = public_locations
            location = public_locations[0] if public_locations else None
            file_value = finding.get("file") or finding.get("path")
            line_value = finding.get("line") or finding.get("startLine")
            end_line = finding.get("endLine")
            if isinstance(location, dict):
                file_value = file_value or location.get("file")
                line_value = line_value or location.get("startLine") or location.get("line")
                end_line = end_line or location.get("endLine")
            file_name = self._security_public_file(file_value)
            if file_name:
                item["file"] = file_name
            if isinstance(line_value, int) and not isinstance(line_value, bool) and line_value > 0:
                item["line"] = line_value
                item["startLine"] = line_value
            if isinstance(end_line, int) and not isinstance(end_line, bool) and end_line > 0:
                item["endLine"] = end_line
            if item:
                result.append(item)
        return result

    def security_list_findings(self, scan_id, cursor=None, limit=50):
        scan_id = _security_scan_key(scan_id)
        integer(limit, "limit", 1, 200)
        if cursor is not None and (not isinstance(cursor, (str, int)) or isinstance(cursor, bool) or
                                   (isinstance(cursor, str) and len(cursor) > 2000) or
                                   (isinstance(cursor, int) and not 0 <= cursor <= 100000)):
            raise BridgeError("INVALID_INPUT: invalid findings cursor.")
        with self.lock:
            row = self._security_scan_record(scan_id)
            cached_json = row["findings_json"] if row and "findings_json" in row.keys() else None
            if cached_json is not None:
                try:
                    cached = json.loads(cached_json)
                except (TypeError, ValueError) as exc:
                    raise BridgeError("SECURITY_STATE_INVALID: persisted findings are invalid.") from exc
                if not isinstance(cached, list):
                    raise BridgeError("SECURITY_STATE_INVALID: persisted findings are not a list.")
                if isinstance(cursor, int):
                    offset = cursor
                elif cursor is None:
                    offset = 0
                elif isinstance(cursor, str) and cursor.isdigit():
                    offset = int(cursor)
                else:
                    raise BridgeError("INVALID_INPUT: persisted findings require a numeric cursor.")
                page = cached[offset:offset + limit]
                end = offset + len(page)
                return {"scanId": scan_id, "findings": page,
                        "nextCursor": end if end < len(cached) else None, "total": len(cached)}

        # Native findings can be slow or unavailable after completion. Never
        # hold the bridge lock while making this optional remote call.
        response = self._security_call("list_findings", scan_id, cursor, limit)
        if isinstance(response, list):
            findings, next_cursor, total = response, None, None
        elif isinstance(response, dict):
            page = response
            for container in (response.get("structuredContent"), response.get("result"), response.get("data")):
                if not isinstance(container, dict):
                    continue
                candidate = container.get("findingsPage", container)
                if isinstance(candidate, dict) and ("findings" in candidate or "items" in candidate):
                    page = candidate
                    break
            findings = page.get("findings") or page.get("items") or []
            next_cursor = page.get("nextCursor", page.get("next_cursor", page.get("nextOffset")))
            total = page.get("total")
        else:
            raise BridgeError("SECURITY_ADAPTER_INVALID: findings response is not an object.")
        result = {"scanId": scan_id, "findings": self._security_public_findings(findings, limit),
                  "nextCursor": self._security_public_value(next_cursor)}
        if isinstance(total, int) and not isinstance(total, bool):
            result["total"] = total
        return result

    def security_export_findings(self, scan_id, format):
        scan_id = _security_scan_key(scan_id)
        if not isinstance(format, str) or format.casefold() not in _SECURITY_FORMATS:
            raise BridgeError("INVALID_INPUT: format must be json, sarif or markdown.")
        format = format.casefold()
        with self.lock:
            response = self._security_call("export_findings", scan_id, format)
            if isinstance(response, str):
                try:
                    export = self._security_public_value(json.loads(response))
                except (TypeError, ValueError):
                    export = re.sub(r"(?i)(token|secret|password)=?[^\s,;}]+", r"\1=[REDACTED]",
                                    _security_redact_text(response))[:200000]
            else:
                export = self._security_public_value(response)
            return {"scanId": scan_id, "format": format, "data": export}

    def show_security_scan_panel(self):
        with self.lock:
            panel = self._security_optional_call("show_security_scan_panel")
            repo = {"name": self.root.name, "gitRepository": git_repository(self.root)}
            active = latest = None
            if isinstance(panel, dict):
                raw_repo = panel.get("repo") or panel.get("repository")
                if isinstance(raw_repo, dict):
                    for key in ("name", "branch", "commit", "gitRepository"):
                        value = raw_repo.get(key)
                        if value is not None:
                            repo[key] = self._security_public_value(value)
                active = panel.get("activeScan") or panel.get("active_scan")
                latest = panel.get("latestScan") or panel.get("latest_scan")
            rows = self.db.execute("SELECT * FROM security_scans ORDER BY updated DESC").fetchall()
            if active is None:
                active_row = next((row for row in rows if row["status"] not in _SECURITY_TERMINAL), None)
                if active_row:
                    try:
                        active, _ = self._security_authoritative(active_row["scan_id"], active_row)
                    except BridgeError:
                        active = self._security_view(active_row["scan_id"], {}, active_row)
            if latest is None and rows:
                row = rows[0]
                try:
                    latest, _ = self._security_authoritative(row["scan_id"], row)
                except BridgeError:
                    latest = self._security_view(row["scan_id"], {}, row)
            if isinstance(active, dict):
                active_id = self._security_find_scan_id(active) or active.get("scanId")
                active = self._security_view(_security_scan_key(active_id), active,
                                             self._security_scan_record(active_id)) if active_id else None
            if isinstance(latest, dict):
                latest_id = self._security_find_scan_id(latest) or latest.get("scanId")
                latest = self._security_view(_security_scan_key(latest_id), latest,
                                             self._security_scan_record(latest_id)) if latest_id else None
            return {
                "panel": "security-scan-v1",
                "repository": repo,
                "supportedTargets": ["codebase", "changes"] if repo["gitRepository"] else ["codebase"],
                "supportedReviewModes": ["standard", "chatgpt_deep"],
                "activeScan": active,
                "latestScan": latest,
            }

    def show_control_panel(self):
        return {"panel_available":True, "project":self.project_info(),
                **self.list_changes(), "task_state":self.tasks.list_tasks()}

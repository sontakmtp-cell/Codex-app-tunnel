"""Fail-closed direct STDIO adapter for the installed Codex Security MCP."""
from __future__ import annotations

from concurrent.futures import Future, TimeoutError as FutureTimeout
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
import time
from typing import Any, Callable, Mapping
import uuid

from runtime import clean_environment


PLUGIN_NAME = "codex-security"
MCP_PROTOCOL_VERSION = "2025-03-26"
DEFAULT_TIMEOUT_SECONDS = 30.0

# Only these native actions are callable through this adapter. In particular,
# the headless Standard/Prompt-Only/Deep entry points are deliberately absent.
NATIVE_TOOL_ALLOWLIST = frozenset({
    "mark_codex_security_scan_handoff_delivered",
    "claim_codex_security_scan_handoff_delivery",
    "open_codex_security_workspace",
    "inspect_codex_security_target",
    "inspect_codex_security_setup",
    "submit_codex_security_setup",
    "start_codex_security_scan",
    "cancel_codex_security_scan_from_app",
    "get_codex_security_scan",
    "list_codex_security_scans",
    "list_codex_security_findings",
    "get_codex_security_scan_context",
    "update_codex_security_scan_context_from_app",
    "update_codex_security_scan_context",
    "update_codex_security_scan_progress",
    "complete_codex_security_scan",
    "fail_codex_security_scan",
    "prepare_codex_security_review_items",
    "list_codex_security_review_items",
    "record_codex_security_discovery_candidates",
    "list_codex_security_candidates",
    "record_codex_security_candidate_validations",
    "record_candidate_attack_paths",
    "record_codex_security_scan_draft",
    "get_codex_security_completed_scan",
    "set_codex_security_finding_triage",
    "set_codex_security_finding_remediation",
    "export_codex_security_findings",
})

# Keep the old descriptive name available to callers that use runtime-style
# constants, without making the allowlist configurable.
ALLOWED_NATIVE_TOOLS = NATIVE_TOOL_ALLOWLIST

REQUIRED_NATIVE_TOOLS = frozenset({
    "mark_codex_security_scan_handoff_delivered",
    "claim_codex_security_scan_handoff_delivery",
    "open_codex_security_workspace",
    "submit_codex_security_setup",
    "start_codex_security_scan",
    "get_codex_security_scan",
    "cancel_codex_security_scan_from_app",
})

MUTATING_NATIVE_TOOLS = frozenset({
    "mark_codex_security_scan_handoff_delivered",
    "claim_codex_security_scan_handoff_delivery",
    "open_codex_security_workspace",
    "submit_codex_security_setup",
    "start_codex_security_scan",
    "cancel_codex_security_scan_from_app",
    "update_codex_security_scan_context_from_app",
    "update_codex_security_scan_context",
    "update_codex_security_scan_progress",
    "complete_codex_security_scan",
    "fail_codex_security_scan",
    "prepare_codex_security_review_items",
    "record_codex_security_discovery_candidates",
    "record_codex_security_candidate_validations",
    "record_candidate_attack_paths",
    "record_codex_security_scan_draft",
    "set_codex_security_finding_triage",
    "set_codex_security_finding_remediation",
})

READ_ONLY_RPC_METHODS = frozenset({"initialize", "tools/list"})
RPC_METHODS = READ_ONLY_RPC_METHODS | {"tools/call"}


class SecurityMcpError(RuntimeError):
    """Safe adapter error; no native diagnostic or sensitive path is exposed."""


class SecurityMcpConfigurationError(SecurityMcpError):
    pass


class SecurityMcpProtocolError(SecurityMcpError):
    pass


class SecurityMcpTimeout(SecurityMcpError):
    pass


class SecurityMcpIdempotencyConflict(SecurityMcpError):
    pass


@dataclass(frozen=True)
class IdempotencyRecord:
    request_id: str
    payload_hash: str
    scan_id: str | None
    status: str
    updated_at: float


@dataclass(frozen=True)
class MutationResult:
    scan_id: str
    status: str
    native_result: Mapping[str, Any] | None
    replayed: bool


def _validate_request_id(request_id: str) -> str:
    if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 256:
        raise SecurityMcpError("INVALID_REQUEST_ID: request_id is required and bounded.")
    if any(ord(char) < 32 or ord(char) == 127 for char in request_id):
        raise SecurityMcpError("INVALID_REQUEST_ID: request_id contains control characters.")
    return request_id


def _payload_hash(payload: Any) -> str:
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SecurityMcpError("INVALID_PAYLOAD: payload must be JSON-serializable.") from exc
    return hashlib.sha256(encoded).hexdigest()


class IdempotencyJournal:
    """Durable request fingerprint journal; payloads themselves are never stored."""

    def __init__(self, directory: Path):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "idempotency.sqlite3"
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS request_map (
                request_id TEXT PRIMARY KEY,
                payload_hash TEXT NOT NULL,
                scan_id TEXT,
                status TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS handoff_map (
                scan_id TEXT PRIMARY KEY,
                claim_token TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def _record(self, row: sqlite3.Row | None) -> IdempotencyRecord | None:
        if row is None:
            return None
        return IdempotencyRecord(
            request_id=str(row["request_id"]),
            payload_hash=str(row["payload_hash"]),
            scan_id=row["scan_id"],
            status=str(row["status"]),
            updated_at=float(row["updated_at"]),
        )

    def lookup(self, request_id: str, payload: Any) -> IdempotencyRecord | None:
        request_id = _validate_request_id(request_id)
        fingerprint = _payload_hash(payload)
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM request_map WHERE request_id=?", (request_id,)
            ).fetchone()
        record = self._record(row)
        if record and record.payload_hash != fingerprint:
            raise SecurityMcpIdempotencyConflict(
                "IDEMPOTENCY_CONFLICT: request_id was already used with another payload."
            )
        return record

    def begin(self, request_id: str, payload: Any) -> IdempotencyRecord:
        request_id = _validate_request_id(request_id)
        fingerprint = _payload_hash(payload)
        now = time.time()
        with self._lock:
            try:
                with self._db:
                    self._db.execute(
                        "INSERT INTO request_map(request_id,payload_hash,scan_id,status,updated_at) "
                        "VALUES(?,?,?,?,?)",
                        (request_id, fingerprint, None, "pending", now),
                    )
            except sqlite3.IntegrityError:
                pass
            row = self._db.execute(
                "SELECT * FROM request_map WHERE request_id=?", (request_id,)
            ).fetchone()
        record = self._record(row)
        if record is None:
            raise SecurityMcpError("IDEMPOTENCY_JOURNAL_FAILED: request was not recorded.")
        if record.payload_hash != fingerprint:
            raise SecurityMcpIdempotencyConflict(
                "IDEMPOTENCY_CONFLICT: request_id was already used with another payload."
            )
        return record

    def complete(self, request_id: str, payload: Any, scan_id: str, status: str) -> IdempotencyRecord:
        request_id = _validate_request_id(request_id)
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise SecurityMcpProtocolError("NATIVE_RESULT_INVALID: scanId is missing.")
        fingerprint = _payload_hash(payload)
        bounded_status = str(status or "running").strip()[:64] or "running"
        with self._lock:
            with self._db:
                row = self._db.execute(
                    "SELECT * FROM request_map WHERE request_id=?", (request_id,)
                ).fetchone()
                if row is None:
                    raise SecurityMcpError("IDEMPOTENCY_JOURNAL_FAILED: request was not started.")
                if row["payload_hash"] != fingerprint:
                    raise SecurityMcpIdempotencyConflict(
                        "IDEMPOTENCY_CONFLICT: request_id was already used with another payload."
                    )
                self._db.execute(
                    "UPDATE request_map SET scan_id=?,status=?,updated_at=? WHERE request_id=?",
                    (scan_id, bounded_status, time.time(), request_id),
                )
                row = self._db.execute(
                    "SELECT * FROM request_map WHERE request_id=?", (request_id,)
                ).fetchone()
        record = self._record(row)
        if record is None:
            raise SecurityMcpError("IDEMPOTENCY_JOURNAL_FAILED: result was not recorded.")
        return record

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def bind_handoff(self, scan_id: str, claim_token: str) -> None:
        if not isinstance(scan_id, str) or not scan_id.strip() or not isinstance(claim_token, str) or not claim_token.strip():
            raise SecurityMcpError("SECURITY_HANDOFF_INVALID: handoff binding is malformed.")
        with self._lock:
            with self._db:
                row = self._db.execute(
                    "SELECT claim_token FROM handoff_map WHERE scan_id=?", (scan_id,)
                ).fetchone()
                if row is not None and row["claim_token"] != claim_token:
                    raise SecurityMcpError("SECURITY_HANDOFF_CONFLICT: scan handoff is owned by another continuation.")
                self._db.execute(
                    "INSERT OR IGNORE INTO handoff_map(scan_id,claim_token) VALUES(?,?)",
                    (scan_id, claim_token),
                )

    def handoff_token(self, scan_id: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT claim_token FROM handoff_map WHERE scan_id=?", (scan_id,)
            ).fetchone()
        return str(row["claim_token"]) if row is not None else None


def _manifest_name(root: Path) -> str | None:
    manifest = root / ".codex-plugin" / "plugin.json"
    if not manifest.is_file():
        return None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data.get("name") if isinstance(data, dict) else None


def validate_plugin_root(candidate: Path) -> Path:
    root = Path(candidate)
    if root.name == "server.mjs":
        root = root.parent.parent
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise SecurityMcpConfigurationError("SECURITY_PLUGIN_INVALID: plugin path is unavailable.") from exc
    server = root / "mcp" / "server.mjs"
    if root.name != PLUGIN_NAME or _manifest_name(root) != PLUGIN_NAME or not server.is_file():
        raise SecurityMcpConfigurationError("SECURITY_PLUGIN_INVALID: installed Security MCP is incomplete.")
    return root


def find_security_plugin(configured: str | Path | None = None) -> Path:
    explicit = configured or os.environ.get("CODEX_SECURITY_PLUGIN_ROOT")
    if explicit:
        return validate_plugin_root(Path(explicit))

    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    active = codex_home / ".tmp" / "plugins" / "plugins" / PLUGIN_NAME
    if active.exists():
        return validate_plugin_root(active)

    candidates = []
    cache = codex_home / "plugins" / "cache"
    if cache.is_dir():
        for provider in sorted(cache.iterdir()):
            candidates.extend(provider.glob(f"{PLUGIN_NAME}/*"))
    valid = []
    for candidate in candidates:
        try:
            valid.append(validate_plugin_root(candidate))
        except SecurityMcpConfigurationError:
            continue
    if not valid:
        raise SecurityMcpConfigurationError("SECURITY_PLUGIN_UNAVAILABLE: installed Security MCP was not found.")
    priority = {"openai-curated-remote": 0, "openai-curated": 1, "chatgpt-global": 2}
    valid.sort(key=lambda root: (priority.get(root.parents[1].name, 99), -root.stat().st_mtime, str(root)))
    return valid[0]


def _validate_node(candidate: Path) -> Path:
    try:
        node = Path(candidate).resolve(strict=True)
    except OSError as exc:
        raise SecurityMcpConfigurationError("SECURITY_NODE_INVALID: bundled Node runtime is unavailable.") from exc
    if node.name.casefold() != "node.exe" or not node.is_file():
        raise SecurityMcpConfigurationError("SECURITY_NODE_INVALID: bundled Node runtime is required.")
    return node


def find_bundled_node(configured: str | Path | None = None) -> Path:
    explicit = configured or os.environ.get("CODEX_MCP_NODE_PATH") or os.environ.get("CODEX_BROWSER_USE_NODE_PATH")
    if explicit:
        return _validate_node(Path(explicit))

    candidates: list[Path] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.extend(Path(local_app_data).glob("OpenAI/Codex/runtimes/cua_node/*/bin/node.exe"))
    cache_root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    candidates.append(Path(cache_root) / "codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe")
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append(Path(user_profile) / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe")
    electron = os.environ.get("CODEX_ELECTRON_RESOURCES_PATH")
    if electron:
        candidates.append(Path(electron) / "cua_node/bin/node.exe")
    cli = os.environ.get("CODEX_CLI_PATH")
    if cli:
        candidates.append(Path(cli).parent / "cua_node/bin/node.exe")

    valid = []
    for candidate in candidates:
        if candidate.is_file():
            valid.append(_validate_node(candidate))
    if not valid:
        raise SecurityMcpConfigurationError("SECURITY_NODE_UNAVAILABLE: bundled Node runtime was not found.")
    return valid[0]


def build_security_environment(state_dir: Path, scan_root: Path) -> dict[str, str]:
    """Return the small inherited environment allowed to the Security server."""
    state_dir = Path(state_dir).resolve()
    scan_root = Path(scan_root).resolve()
    if not scan_root.is_dir():
        raise SecurityMcpConfigurationError("SECURITY_TARGET_INVALID: scan root is unavailable.")
    cache_dir = state_dir / "bridge-journal"
    cache_dir.mkdir(parents=True, exist_ok=True)
    env = clean_environment(cache_dir)
    env.pop("CODEX_HOME", None)
    env["CODEX_SECURITY_STATE_DIR"] = str(state_dir)
    env["CODEX_SECURITY_SCAN_ROOT"] = str(scan_root)
    env["CODEX_SECURITY_SURFACE"] = "app"
    if os.name != "nt" and os.environ.get("HOME"):
        env["HOME"] = os.environ["HOME"]
    return env


def _make_job():
    if os.name != "nt":
        return None
    from windows_job import OwnedJob
    return OwnedJob()


def _extract_scan_id(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if not isinstance(value, Mapping):
        return None
    if isinstance(value.get("scanId"), str) and value["scanId"].strip():
        return value["scanId"].strip()
    for container in (value.get("structuredContent"), value.get("result"), value):
        if not isinstance(container, Mapping):
            continue
        workspace = container.get("workspace")
        if not isinstance(workspace, Mapping):
            continue
        results = workspace.get("results")
        if isinstance(results, Mapping) and isinstance(results.get("scanId"), str):
            return results["scanId"].strip() or None
    return None


def _extract_status(value: Any) -> str:
    if isinstance(value, Mapping):
        for container in (value, value.get("structuredContent"), value.get("result")):
            if isinstance(container, Mapping) and isinstance(container.get("status"), str):
                return container["status"].strip()[:64] or "running"
            if isinstance(container, Mapping):
                workspace = container.get("workspace")
                if isinstance(workspace, Mapping) and isinstance(workspace.get("status"), str):
                    return workspace["status"].strip()[:64] or "running"
    return "running"


class SecurityMcpAdapter:
    """One owned codex-security MCP process and its fixed native facade."""

    def __init__(
        self,
        state_dir: Path,
        scan_root: Path,
        *,
        plugin_root: str | Path | None = None,
        node_path: str | Path | None = None,
        call_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.state_dir = Path(state_dir).resolve()
        self.scan_root = Path(scan_root).resolve()
        if not self.scan_root.is_dir():
            raise SecurityMcpConfigurationError("SECURITY_TARGET_INVALID: scan root is unavailable.")
        if self.state_dir == self.scan_root or self.state_dir.is_relative_to(self.scan_root):
            raise SecurityMcpConfigurationError("SECURITY_STATE_INVALID: state must be outside the scan root.")
        self.security_state_dir = self.state_dir / "security"
        self.workbench_state_dir = self.security_state_dir / "workbench-state"
        self.scans_dir = self.security_state_dir / "scans"
        self.journal_dir = self.security_state_dir / "bridge-journal"
        for directory in (self.workbench_state_dir, self.scans_dir, self.journal_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self.plugin_root = plugin_root
        self.node_path = node_path
        self.call_timeout = float(call_timeout)
        self.journal = IdempotencyJournal(self.journal_dir)
        self._state_lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._pending: dict[int, Future] = {}
        self._sequence = 0
        self._process = None
        self._job = None
        self._reader_thread = None
        self._stderr_thread = None
        self._status = "stopped"
        self._tools: dict[str, dict[str, Any]] = {}

    @property
    def status(self) -> str:
        return self._status

    @property
    def process(self):
        return self._process

    def start(self) -> "SecurityMcpAdapter":
        with self._state_lock:
            if self._process is not None and self._process.poll() is None:
                return self
        plugin = find_security_plugin(self.plugin_root)
        node = find_bundled_node(self.node_path)
        server = plugin / "mcp" / "server.mjs"
        # The project is passed to app-only native tools; scan artifacts stay
        # in the bridge-owned state directory outside the selected project.
        env = build_security_environment(self.workbench_state_dir, self.scans_dir)
        job = None
        process = None
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            job = _make_job()
            if job:
                flags |= 0x00000004  # CREATE_SUSPENDED
            argv = [str(node), str(server), "--stdio"]
            if any(Path(argument).name.casefold() == "codex.exe" for argument in argv):
                raise SecurityMcpConfigurationError("SECURITY_RUNTIME_BLOCKED: Codex executable is not allowed.")
            process = subprocess.Popen(
                argv,
                cwd=str(plugin),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=flags,
            )
            if job:
                job.assign_and_resume(process)
        except SecurityMcpError:
            if process and process.poll() is None:
                process.kill()
            if job:
                job.close()
            raise
        except Exception as exc:
            if process and process.poll() is None:
                process.kill()
            if job:
                job.close()
            raise SecurityMcpError("SECURITY_RUNTIME_START_FAILED: Security MCP did not start.") from exc

        with self._state_lock:
            self._process = process
            self._job = job
            self._status = "connecting"
        self._reader_thread = threading.Thread(target=self._reader, args=(process,), daemon=True)
        self._reader_thread.start()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, args=(process,), daemon=True)
        self._stderr_thread.start()
        try:
            self.call(
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "chatgpt_security_bridge", "version": "1.0.0"},
                },
            )
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            tools = self._fetch_tools()
            missing = REQUIRED_NATIVE_TOOLS - set(tools)
            if missing:
                raise SecurityMcpProtocolError("SECURITY_CAPABILITY_MISSING: required native tool is unavailable.")
            with self._state_lock:
                self._tools = {name: tools[name] for name in NATIVE_TOOL_ALLOWLIST if name in tools}
                self._status = "connected"
        except Exception:
            self.close()
            raise
        return self

    def _fetch_tools(self) -> dict[str, dict[str, Any]]:
        cursor = None
        tools: dict[str, dict[str, Any]] = {}
        while True:
            params = {} if cursor is None else {"cursor": cursor}
            result = self.call("tools/list", params)
            if not isinstance(result, Mapping) or not isinstance(result.get("tools"), list):
                raise SecurityMcpProtocolError("SECURITY_PROTOCOL_INVALID: tools/list response is invalid.")
            for tool in result["tools"]:
                if isinstance(tool, Mapping) and isinstance(tool.get("name"), str):
                    tools[tool["name"]] = dict(tool)
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def list_native_tools(self) -> list[dict[str, Any]]:
        if self.status != "connected":
            raise SecurityMcpError("SECURITY_RUNTIME_UNAVAILABLE: adapter is not connected.")
        return [dict(tool) for tool in self._tools.values()]

    def _send(self, message: Mapping[str, Any]) -> None:
        with self._write_lock:
            process = self._process
            if process is None or process.poll() is not None or process.stdin is None:
                raise SecurityMcpError("SECURITY_RUNTIME_LOST: operation was not replayed.")
            process.stdin.write((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))
            process.stdin.flush()

    def call(self, method: str, params: Mapping[str, Any] | None = None, timeout: float | None = None) -> Any:
        if method not in RPC_METHODS:
            raise SecurityMcpError("SECURITY_RPC_BLOCKED: RPC method is not exported.")
        with self._state_lock:
            if self._process is None or self._process.poll() is not None:
                raise SecurityMcpError("SECURITY_RUNTIME_LOST: operation was not replayed.")
            self._sequence += 1
            request_id = self._sequence
            future: Future = Future()
            self._pending[request_id] = future
        try:
            self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params or {})})
            return future.result(timeout=self.call_timeout if timeout is None else timeout)
        except FutureTimeout as exc:
            with self._state_lock:
                self._pending.pop(request_id, None)
            self.close()
            raise SecurityMcpTimeout("SECURITY_RUNTIME_TIMEOUT: result unknown; mutation was not replayed.") from exc
        finally:
            with self._state_lock:
                self._pending.pop(request_id, None)

    def _validate_tool(self, name: str, arguments: Mapping[str, Any]) -> None:
        if name not in NATIVE_TOOL_ALLOWLIST:
            raise SecurityMcpError("SECURITY_TOOL_BLOCKED: native tool is not in the fixed allowlist.")
        if not isinstance(arguments, Mapping):
            raise SecurityMcpError("SECURITY_ARGUMENTS_INVALID: tool arguments must be an object.")
        if name == "open_codex_security_workspace" and arguments.get("mode") == "deep":
            raise SecurityMcpError("SECURITY_NATIVE_DEEP_DISABLED: native Deep is outside V1.")
        if name == "start_codex_security_scan" and {"model", "reasoningEffort"} & set(arguments):
            raise SecurityMcpError("SECURITY_NATIVE_MODEL_BLOCKED: app-only start does not accept a model.")

    def _call_native_tool(self, name: str, arguments: Mapping[str, Any], timeout: float | None = None) -> dict[str, Any]:
        self._validate_tool(name, arguments)
        result = self.call("tools/call", {"name": name, "arguments": dict(arguments)}, timeout)
        if not isinstance(result, dict):
            raise SecurityMcpProtocolError("SECURITY_PROTOCOL_INVALID: native tool response is invalid.")
        if result.get("isError"):
            raise SecurityMcpProtocolError("SECURITY_NATIVE_REJECTED: native tool rejected the operation.")
        return result

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        request_id: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        args = dict(arguments or {})
        self._validate_tool(name, args)
        if name in MUTATING_NATIVE_TOOLS:
            if request_id is None:
                raise SecurityMcpError("IDEMPOTENCY_REQUIRED: mutation requires request_id.")
            _validate_request_id(request_id)
        return self._call_native_tool(name, args, timeout)

    def call_mutation(
        self,
        name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        *,
        payload: Any | None = None,
        reconcile: Callable[[IdempotencyRecord], Any] | None = None,
        result_extractor: Callable[[Any], str | None] = _extract_scan_id,
        timeout: float | None = None,
    ) -> MutationResult:
        if name not in MUTATING_NATIVE_TOOLS:
            raise SecurityMcpError("SECURITY_MUTATION_BLOCKED: tool is not a mutation in the fixed facade.")
        args = dict(arguments)
        self._validate_tool(name, args)
        _validate_request_id(request_id)
        journal_payload = payload if payload is not None else {"tool": name, "arguments": args}
        existing = self.journal.lookup(request_id, journal_payload)
        if existing is None:
            existing = self.journal.begin(request_id, journal_payload)
            is_new = True
        else:
            is_new = False

        if existing.scan_id:
            return MutationResult(existing.scan_id, existing.status, None, True)
        if not is_new and reconcile is None:
            raise SecurityMcpError("IDEMPOTENCY_UNCERTAIN: check authoritative Security state before retry.")
        if not is_new and reconcile is not None:
            authoritative = reconcile(existing)
            scan_id = result_extractor(authoritative) if authoritative is not None else None
            if scan_id:
                record = self.journal.complete(
                    request_id, journal_payload, scan_id, _extract_status(authoritative)
                )
                return MutationResult(record.scan_id or scan_id, record.status, None, True)

        try:
            native_result = self._call_native_tool(name, args, timeout)
        except SecurityMcpTimeout:
            # The pending row is deliberately retained for a later authoritative lookup.
            raise
        scan_id = result_extractor(native_result)
        if not scan_id:
            raise SecurityMcpProtocolError("NATIVE_RESULT_INVALID: workspace.results.scanId is missing.")
        record = self.journal.complete(
            request_id, journal_payload, scan_id, _extract_status(native_result)
        )
        return MutationResult(record.scan_id or scan_id, record.status, native_result, False)

    def _reader(self, process) -> None:
        try:
            for raw_line in process.stdout:
                try:
                    message = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    self._fail_pending(SecurityMcpProtocolError("SECURITY_PROTOCOL_INVALID: malformed MCP message."))
                    break
                if not isinstance(message, Mapping):
                    continue
                if "method" in message and "id" in message:
                    try:
                        self._send({
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "error": {"code": -32601, "message": "Security bridge does not approve server requests."},
                        })
                    except SecurityMcpError:
                        pass
                    continue
                if "id" in message:
                    with self._state_lock:
                        future = self._pending.get(message["id"])
                    if future and not future.done():
                        if "error" in message:
                            future.set_exception(SecurityMcpProtocolError("SECURITY_NATIVE_REJECTED: MCP request failed."))
                        else:
                            future.set_result(message.get("result", {}))
        except (OSError, AttributeError, TypeError, ValueError, BrokenPipeError):
            pass
        finally:
            self._fail_pending(SecurityMcpError("SECURITY_RUNTIME_LOST: operation was not replayed."))
            with self._state_lock:
                if self._status != "stopped":
                    self._status = "disconnected"

    def _fail_pending(self, error: Exception) -> None:
        with self._state_lock:
            pending = list(self._pending.values())
        for future in pending:
            if not future.done():
                future.set_exception(error)

    @staticmethod
    def _drain_stderr(process) -> None:
        try:
            while process.stderr.read(8192):
                pass
        except (OSError, AttributeError, ValueError):
            pass

    def close(self) -> None:
        with self._state_lock:
            process, job = self._process, self._job
            self._process = None
            self._job = None
            self._status = "stopped"
        self._fail_pending(SecurityMcpError("SECURITY_RUNTIME_LOST: operation was not replayed."))
        if job:
            job.close()
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass

    def shutdown(self) -> None:
        self.close()
        self.journal.close()

    def _ensure_connected(self) -> None:
        if self.status != "connected":
            self.start()

    @staticmethod
    def _nested(value: Any) -> list[Mapping[str, Any]]:
        if not isinstance(value, Mapping):
            return []
        result: list[Mapping[str, Any]] = []
        pending: list[Mapping[str, Any]] = [value]
        seen: set[int] = set()
        while pending:
            current = pending.pop(0)
            if id(current) in seen:
                continue
            seen.add(id(current))
            result.append(current)
            for key in ("structuredContent", "result", "data", "workspace", "results", "scan"):
                child = current.get(key)
                if isinstance(child, Mapping):
                    pending.append(child)
        return result

    @classmethod
    def _workspace_id(cls, value: Any) -> str | None:
        for item in cls._nested(value):
            workspace = item.get("workspace")
            if isinstance(workspace, Mapping) and isinstance(workspace.get("id"), str):
                return workspace["id"].strip() or None
            if isinstance(item.get("id"), str) and item.get("mode") in {"standard", "diff"}:
                return item["id"].strip() or None
        return None

    @staticmethod
    def _native_request_id(request_id: str, tool: str, payload: Any) -> str:
        return f"security-{_payload_hash([request_id, tool, payload])[:48]}"

    def _mutation(self, tool: str, arguments: Mapping[str, Any], request_id: str,
                  payload: Any | None = None,
                  result_extractor: Callable[[Any], str | None] = _extract_scan_id,
                  reconcile: Callable[[IdempotencyRecord], Any] | None = None) -> MutationResult:
        return self.call_mutation(
            tool,
            arguments,
            self._native_request_id(request_id, tool, payload if payload is not None else arguments),
            payload=payload if payload is not None else {"tool": tool, "arguments": dict(arguments)},
            reconcile=reconcile,
            result_extractor=result_extractor,
        )

    @classmethod
    def _handoff_state(cls, value: Any) -> Mapping[str, Any] | None:
        for item in cls._nested(value):
            if isinstance(item.get("scanId"), str) and (
                "handoffStatus" in item or "handoffClaimToken" in item
            ):
                return item
        return None

    @staticmethod
    def _handoff_token(request_id: str, payload: Any) -> str:
        # Deterministic and non-secret: a restart can finish a handoff without
        # persisting the opaque native token in the bridge journal.
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"codex-security-handoff:{request_id}:{_payload_hash(payload)}"))

    def _handoff_result_extractor(self, scan_id: str, expected_status: str,
                                  expected_token: str) -> Callable[[Any], str | None]:
        def extract(value: Any) -> str | None:
            state = self._handoff_state(value)
            if not state or state.get("scanId") != scan_id:
                return None
            if state.get("handoffStatus") != expected_status:
                return None
            if state.get("handoffClaimToken") != expected_token:
                return None
            return scan_id
        return extract

    def _ensure_handoff(self, scan_id: str, request_id: str, payload: Any) -> str | None:
        state = self._handoff_state(self.get_scan(scan_id))
        if not state:
            raise SecurityMcpProtocolError("SECURITY_HANDOFF_INVALID: native scan handoff state is missing.")
        status = state.get("progress", {}).get("status") if isinstance(state.get("progress"), Mapping) else None
        if status in {"cancelled", "canceled", "completed", "failed", "interrupted"}:
            return None
        handoff_status = state.get("handoffStatus")
        current_token = state.get("handoffClaimToken")
        expected_token = self._handoff_token(request_id, payload)
        if handoff_status == "delivered":
            if current_token is None:
                return None
            if not isinstance(current_token, str):
                raise SecurityMcpProtocolError("SECURITY_HANDOFF_INVALID: native handoff token is malformed.")
            bound_token = self.journal.handoff_token(scan_id)
            if bound_token is None:
                raise SecurityMcpError("SECURITY_HANDOFF_UNAVAILABLE: native scan handoff is not owned by this bridge.")
            if current_token != bound_token or current_token != expected_token:
                raise SecurityMcpError("SECURITY_HANDOFF_CONFLICT: scan handoff is owned by another continuation.")
            return current_token
        if handoff_status != "pending":
            raise SecurityMcpProtocolError("SECURITY_HANDOFF_INVALID: native handoff is not claimable.")
        token = expected_token
        if current_token is not None and current_token != token:
            raise SecurityMcpError("SECURITY_HANDOFF_CONFLICT: scan handoff is owned by another continuation.")
        self.journal.bind_handoff(scan_id, token)
        claim_payload = {"operation": "claim_handoff", "scanId": scan_id, "claimToken": token}
        self._mutation(
            "claim_codex_security_scan_handoff_delivery",
            {"scanId": scan_id, "claimToken": token},
            request_id,
            claim_payload,
            result_extractor=self._handoff_result_extractor(scan_id, "pending", token),
            reconcile=lambda _record: self.get_scan(scan_id),
        )
        delivered_payload = {"operation": "deliver_handoff", "scanId": scan_id, "claimToken": token}
        self._mutation(
            "mark_codex_security_scan_handoff_delivered",
            {"scanId": scan_id, "claimToken": token},
            request_id,
            delivered_payload,
            result_extractor=self._handoff_result_extractor(scan_id, "delivered", token),
            reconcile=lambda _record: self.get_scan(scan_id),
        )
        return token

    def _scan_handoff_token(self, scan_id: str) -> str | None:
        state = self._handoff_state(self.get_scan(scan_id))
        if not state:
            raise SecurityMcpProtocolError("SECURITY_HANDOFF_INVALID: native scan handoff state is missing.")
        if state.get("handoffStatus") != "delivered":
            raise SecurityMcpError("SECURITY_HANDOFF_UNAVAILABLE: scan continuation has not been delivered.")
        token = state.get("handoffClaimToken")
        if token is not None and not isinstance(token, str):
            raise SecurityMcpProtocolError("SECURITY_HANDOFF_INVALID: native handoff token is malformed.")
        bound_token = self.journal.handoff_token(scan_id)
        if token is not None and (bound_token is None or token != bound_token):
            raise SecurityMcpError("SECURITY_HANDOFF_CONFLICT: scan handoff is owned by another continuation.")
        return token

    def _find_authoritative_start(self, mode: str) -> str | None:
        result = self.call_tool("list_codex_security_scans", {"limit": 50, "mode": mode})
        matches = []
        for item in self._nested(result):
            scans = item.get("scans")
            if not isinstance(scans, list):
                continue
            for scan in scans:
                if not isinstance(scan, Mapping):
                    continue
                if scan.get("mode") != mode or scan.get("scope") not in (None, "."):
                    continue
                if scan.get("targetPath") != str(self.scan_root):
                    continue
                scan_id = scan.get("scanId")
                if isinstance(scan_id, str) and scan_id.strip():
                    matches.append(scan_id.strip())
        if len(matches) > 1:
            raise SecurityMcpError("SECURITY_IDEMPOTENCY_UNCERTAIN: multiple authoritative scans match the retry.")
        return matches[0] if matches else None

    def start_scan(self, mode: str, target: Mapping[str, Any], user_context: str | None,
                   request_id: str) -> dict[str, Any]:
        if mode not in {"standard", "diff"}:
            raise SecurityMcpError("SECURITY_MODE_BLOCKED: only standard or diff native setup is allowed.")
        if not isinstance(target, Mapping) or target.get("kind") not in {"codebase", "working_tree"}:
            raise SecurityMcpError("SECURITY_TARGET_INVALID: target kind is not supported.")
        _validate_request_id(request_id)
        payload = {"operation": "start", "mode": mode, "target": dict(target),
                   "userContext": user_context}
        existing = self.journal.lookup(request_id, payload)
        if existing:
            if existing.scan_id:
                self._ensure_connected()
                self._ensure_handoff(existing.scan_id, request_id, payload)
                return {"structuredContent": {"workspace": {"results": {"scanId": existing.scan_id}}},
                        "status": existing.status}
        self._ensure_connected()
        if existing and not existing.scan_id:
            authoritative = self._find_authoritative_start(mode)
            if authoritative:
                record = self.journal.complete(request_id, payload, authoritative, "running")
                self._ensure_handoff(authoritative, request_id, payload)
                return {"structuredContent": {"workspace": {"results": {"scanId": authoritative}}},
                        "status": record.status}
        if existing is None:
            self.journal.begin(request_id, payload)

        diff_target = {"kind": "working_tree"} if target.get("kind") == "working_tree" else None
        open_args: dict[str, Any] = {"mode": mode, "scope": ".", "targetPath": str(self.scan_root)}
        if diff_target:
            open_args["diffTarget"] = diff_target
        if isinstance(user_context, str) and user_context:
            open_args["userContext"] = user_context
        open_payload = {"operation": "open", "mode": mode, "target": dict(target),
                        "userContext": user_context}
        opened = self._mutation("open_codex_security_workspace", open_args, request_id,
                                open_payload, result_extractor=self._workspace_id)
        workspace_id = opened.scan_id
        if not workspace_id:
            raise SecurityMcpProtocolError("SECURITY_START_FAILED: workspace.id is missing.")

        setup_args: dict[str, Any] = {
            "sessionId": workspace_id, "mode": mode, "scope": ".", "targetPath": str(self.scan_root),
        }
        if diff_target:
            setup_args["diffTarget"] = diff_target
        if isinstance(user_context, str) and user_context:
            setup_args["userContext"] = user_context
        setup_payload = {"operation": "setup", "mode": mode, "target": dict(target),
                         "userContext": user_context, "workspaceId": workspace_id}
        self._mutation("submit_codex_security_setup", setup_args, request_id, setup_payload,
                       result_extractor=lambda _value: workspace_id)
        result = self._mutation("start_codex_security_scan", {"sessionId": workspace_id}, request_id, payload)
        self._ensure_handoff(result.scan_id, request_id, payload)
        self.journal.complete(request_id, payload, result.scan_id, result.status)
        if result.native_result is not None:
            return dict(result.native_result)
        return {"structuredContent": {"workspace": {"id": workspace_id,
                                                       "results": {"scanId": result.scan_id}}},
                "status": result.status}

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        _validate_request_id(scan_id)
        self._ensure_connected()
        return self.call_tool("get_codex_security_scan", {"scanId": scan_id})

    def continue_scan(self, scan_id: str) -> dict[str, Any]:
        return self.get_scan(scan_id)

    @staticmethod
    def _empty_coverage() -> dict[str, Any]:
        return {"completeness": "partial", "surfaces": [], "explicitExclusions": [], "deferred": []}

    @staticmethod
    def _native_threat_model(value: Mapping[str, Any]) -> dict[str, Any]:
        """Normalize ChatGPT's common snake_case model into native draft text."""
        model = dict(value)
        for source, target in (
            ("trust_boundaries", "trustBoundaries"),
            ("attacker_capabilities", "attackerCapabilities"),
            ("security_objectives", "securityObjectives"),
            ("open_questions", "openQuestions"),
            ("scope_limit", "scopeLimit"),
        ):
            if target not in model and source in model:
                model[target] = model[source]

        for field in ("assets", "trustBoundaries", "attackerCapabilities", "securityObjectives", "assumptions"):
            values = model.get(field)
            if not isinstance(values, list):
                continue
            normalized = []
            for item in values:
                if isinstance(item, str):
                    text = item.strip()
                else:
                    text = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                if text:
                    normalized.append(text[:12000])
            model[field] = normalized

        summary = model.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            limit = model.get("scopeLimit") or model.get("scope_limit")
            model["summary"] = (
                f"Scope limitation: {limit}" if isinstance(limit, str) and limit.strip()
                else "Threat model supplied by ChatGPT Web; see the structured model fields."
            )[:12000]
        return model

    def _commit_native_phase(self, scan_id: str, phase: str, phase_data: Mapping[str, Any],
                             request_id: str) -> None:
        data = dict(phase_data)
        handoff_token = self._scan_handoff_token(scan_id)
        coverage = data.get("coverage")
        coverage = dict(coverage) if isinstance(coverage, Mapping) else self._empty_coverage()
        for key, default in (("completeness", "partial"), ("surfaces", []),
                              ("explicitExclusions", []), ("deferred", [])):
            coverage.setdefault(key, default)
        if phase != "finalization":
            candidates = data.get("candidates")
            if isinstance(candidates, list) and candidates:
                deferred = list(coverage.get("deferred", []))
                for index, candidate in enumerate(candidates[:200]):
                    if not isinstance(candidate, Mapping):
                        continue
                    identifier = (candidate.get("candidateId") or candidate.get("candidate_id") or
                                  candidate.get("id") or f"{phase}-{index + 1}")
                    deferred.append({"id": str(identifier)[:512],
                                     "reason": f"{phase} checkpoint awaits the next workflow phase.",
                                     "candidate": dict(candidate)})
                coverage["deferred"] = deferred[:500]
        draft: dict[str, Any] = {
            "scanId": scan_id,
            "complete": phase == "finalization",
            "findings": data.get("findings", []),
            "coverage": coverage,
        }
        if handoff_token:
            draft["handoffClaimToken"] = handoff_token
        if isinstance(data.get("threatModel"), Mapping):
            draft["threatModel"] = self._native_threat_model(data["threatModel"])
        self._mutation("record_codex_security_scan_draft", draft, request_id,
                        {"operation": "phase", "phase": phase, "scanId": scan_id, "draft": draft},
                        result_extractor=lambda _value: scan_id)

        native_phase = {
            "preflight": "preflight", "inventory": "preflight", "threat_model": "threat_model",
            "discovery": "discovery", "attack_surface": "discovery", "auth_data_flow": "discovery",
            "injection_file_process_network_state": "discovery", "deduplicate": "discovery",
            "validation": "validation", "attack_path": "attack_path", "finalization": "reporting",
        }.get(phase)
        if native_phase is None:
            raise SecurityMcpError("SECURITY_PHASE_INVALID: phase is not supported.")
        progress: dict[str, Any] = {"scanId": scan_id, "phase": native_phase,
                                     "phaseItemsTotal": 1, "phaseItemsCompleted": 1,
                                     "phaseProgressUnit": "report_artifacts" if phase == "finalization" else "checks"}
        if handoff_token:
            progress["handoffClaimToken"] = handoff_token
        if phase in {"attack_surface", "auth_data_flow", "injection_file_process_network_state"}:
            # chatgpt_deep is intentionally backed by the app-only standard
            # native session; deepReviewPass belongs to native Deep and must
            # never be sent on this zero-Codex-usage path.
            deep_phases = ("attack_surface", "auth_data_flow",
                           "injection_file_process_network_state")
            progress["phaseItemsTotal"] = len(deep_phases)
            progress["phaseItemsCompleted"] = deep_phases.index(phase) + 1
            progress["phaseProgressUnit"] = "review_receipts"
        if phase != "deduplicate":
            # deduplicate has no native standard equivalent; its draft is the
            # authoritative checkpoint until the next native phase advances.
            self._mutation("update_codex_security_scan_progress", progress, request_id,
                            {"operation": "progress", "phase": phase, "scanId": scan_id, "progress": progress},
                            result_extractor=lambda _value: scan_id)

    def commit_phase(self, scan_id: str, phase: str, phase_data: Mapping[str, Any],
                     request_id: str) -> dict[str, Any]:
        if not isinstance(phase_data, Mapping):
            raise SecurityMcpError("SECURITY_PHASE_INVALID: phase data must be an object.")
        _validate_request_id(request_id)
        self._ensure_connected()
        self._commit_native_phase(scan_id, phase, phase_data, request_id)
        return self.get_scan(scan_id)

    def complete_scan(self, scan_id: str, request_id: str) -> dict[str, Any]:
        _validate_request_id(request_id)
        self._ensure_connected()
        arguments: dict[str, Any] = {"scanId": scan_id}
        handoff_token = self._scan_handoff_token(scan_id)
        if handoff_token:
            arguments["handoffClaimToken"] = handoff_token
        result = self._mutation("complete_codex_security_scan", arguments, request_id,
                                {"operation": "complete", "scanId": scan_id})
        return dict(result.native_result or {"scanId": scan_id, "status": "completed"})

    def cancel_scan(self, scan_id: str, request_id: str) -> dict[str, Any]:
        _validate_request_id(request_id)
        self._ensure_connected()
        result = self._mutation("cancel_codex_security_scan_from_app", {"scanId": scan_id}, request_id,
                                {"operation": "cancel", "scanId": scan_id})
        return dict(result.native_result or {"scanId": scan_id, "status": "cancelled"})

    def list_findings(self, scan_id: str, cursor: str | int | None = None, limit: int = 50) -> dict[str, Any]:
        self._ensure_connected()
        arguments: dict[str, Any] = {"scanId": scan_id, "limit": max(1, min(int(limit), 50))}
        if isinstance(cursor, int):
            arguments["offset"] = max(0, cursor)
        elif isinstance(cursor, str) and cursor.isdigit():
            arguments["offset"] = int(cursor)
        return self.call_tool("list_codex_security_findings", arguments)

    def export_findings(self, scan_id: str, format: str) -> Any:
        if format not in {"json", "sarif", "markdown"}:
            raise SecurityMcpError("SECURITY_FORMAT_INVALID: unsupported export format.")
        self._ensure_connected()
        native_format = "json" if format == "markdown" else format
        result = self.call_tool("export_codex_security_findings",
                                {"scanId": scan_id, "format": native_format})
        if format != "markdown":
            return result
        return "# Security findings\n\n```json\n" + json.dumps(result, ensure_ascii=False, indent=2) + "\n```"

    def __enter__(self) -> "SecurityMcpAdapter":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()

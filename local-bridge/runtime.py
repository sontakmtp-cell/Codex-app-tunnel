"""One owned Codex App Server connection; no model turns or API passthrough."""
from __future__ import annotations

import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import uuid
import threading
import tomllib


class BridgeError(ValueError):
    """An error whose message is safe to return to a tool caller."""


ALLOWED_METHODS = frozenset({
    "initialize", "command/exec", "command/exec/terminate", "fs/readFile",
    "fs/watch", "fs/unwatch", "skills/list", "thread/list", "thread/read",
    "thread/turns/list", "thread/start", "thread/unsubscribe",
    "mcpServerStatus/list", "mcpServer/tool/call", "permissionProfile/list",
})
ENV_NAMES = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP", "TMP",
             "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "APPDATA",
             "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA", "SYSTEMDRIVE"}


def clean_environment(cache: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in ENV_NAMES}
    env.update(TEMP=str(cache), TMP=str(cache), PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
               PYTHONDONTWRITEBYTECODE="1", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return env


def find_codex(configured: str | None = None) -> Path:
    if configured:
        candidates = [Path(configured)]
    else:
        base = Path(os.environ.get("LOCALAPPDATA", "")) / "OpenAI/Codex/bin"
        candidates = sorted(base.glob("*/codex.exe"), key=lambda p: p.stat().st_mtime, reverse=True)
        found = shutil.which("codex.exe")
        if found:
            candidates.append(Path(found))
        npm = Path(os.environ.get("APPDATA", "")) / "npm/node_modules/@openai"
        candidates.extend(npm.glob("codex*/vendor/*/codex/codex.exe"))
        candidates.extend(npm.glob("codex/node_modules/@openai/codex-*/vendor/*/bin/codex.exe"))
    for candidate in candidates:
        if candidate.is_file() and candidate.suffix.lower() == ".exe":
            return candidate.resolve()
    raise BridgeError("RUNTIME_UNAVAILABLE: no installed codex.exe; configure codex_executable locally.")


def process_overrides(root: Path, cache: Path, runtime_roots: list[Path]) -> list[str]:
    from files import BLOCKED_SUFFIXES, SECRET_NAMES, SECRET_PREFIXES, SENSITIVE_DIRECTORIES, git_repository
    # CLI overrides affect this child only, never the desktop's saved configuration.
    home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    sources = [home / "config.toml"] + [p / ".codex/config.toml" for p in reversed([root, *root.parents])]
    servers, plugins = set(), set()
    for path in sources:
        if path.is_file():
            config = tomllib.loads(path.read_text(encoding="utf-8"))
            servers.update(config.get("mcp_servers", {}))
            plugins.update(config.get("plugins", {}))
    settings = {
        "approval_policy": '"never"', "approvals_reviewer": '"user"',
        "windows.sandbox": '"elevated"', "default_permissions": '"bridge"',
        "features.apps": "false", "features.codex_hooks": "false",
        "features.analytics": "false", "analytics.enabled": "false",
        "shell_environment_policy.inherit": '"none"',
        "mcp_servers": '{openaiDeveloperDocs={url="https://developers.openai.com/mcp",enabled=true,enabled_tools=["search_openai_docs","fetch_openai_doc"]}}',
        "permissions.bridge.network.enabled": "false",
    }
    settings["plugins"] = "{" + ",".join(json.dumps(name) + "={enabled=false}" for name in plugins) + "}"
    # Tables merge with user/project config; an empty table would not disable inherited servers.
    disabled = ",".join(json.dumps(name) + "={enabled=false}" for name in servers - {"openaiDeveloperDocs"})
    if disabled:
        settings["mcp_servers"] = settings["mcp_servers"][:-1] + "," + disabled + "}"
    fs = {":root": "deny", ":minimal": "read", ":tmpdir": "deny", ":slash_tmp": "deny",
          str(root): "write", str(cache): "write"}
    for path in runtime_roots:
        fs[str(path)] = "read"
    # Windows setup creates missing permission roots. Never create .git in a plain folder.
    if git_repository(root):
        fs[str(root / ".git")] = "read"
    patterns = list(SENSITIVE_DIRECTORIES | SECRET_NAMES) + [p+"*" for p in SECRET_PREFIXES] + ["*"+s for s in BLOCKED_SUFFIXES]
    for pattern in patterns:
        for name in (pattern, "**/"+pattern):
            fs[str(root / name)] = "deny"
    settings["permissions.bridge.filesystem"] = "{glob_scan_max_depth=32," + ",".join(
        json.dumps(k) + "=" + json.dumps(v) for k, v in fs.items()) + "}"
    settings["shell_environment_policy.set"] = "{" + ",".join(
        json.dumps(k) + "=" + json.dumps(v) for k, v in clean_environment(cache).items()) + "}"
    return [item for key, value in settings.items() for item in ("-c", key + "=" + value)]


class AppServer:
    def __init__(self, root: Path, state: Path, executable: str | None = None,
                 runtime_roots: list[Path] | None = None):
        self.root, self.state = root, state
        self.executable = executable
        self.runtime_roots = runtime_roots or []
        self.process = None
        self.job = None
        self.pending = {}
        self.lock = threading.RLock()
        self.listeners = []
        self.sequence = 0
        self.status = "stopped"
        self.version = None
        self.error = None
        self.command_ready = False
        self.command_error = "NOT_VERIFIED: run the runtime doctor."
        self.methods = set()

    def start(self):
        exe = find_codex(self.executable)
        cache = self.state / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        env = clean_environment(cache)
        if os.environ.get("CODEX_HOME"):
            env["CODEX_HOME"] = os.environ["CODEX_HOME"]
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        self.version = subprocess.check_output([str(exe), "--version"], env=env,
                                              creationflags=flags, timeout=10).decode().strip()
        schema_dir = self.state / "schema"
        subprocess.run([str(exe), "app-server", "generate-json-schema", "--experimental", "--out", str(schema_dir)],
                       env=env, creationflags=flags, capture_output=True, check=True, timeout=25)
        schema = json.loads((schema_dir / "v2/CommandExecParams.json").read_text())
        required = {"permissionProfile", "processId", "streamStdoutStderr", "env"}
        if not required <= schema["properties"].keys():
            raise BridgeError("UNSUPPORTED_CAPABILITY: installed Codex lacks protected streaming commands.")
        self.methods = {"command", "watch", "skills", "history", "docs"}
        argv = [str(exe), "app-server", "--stdio", *process_overrides(self.root, cache, self.runtime_roots)]
        if os.name == "nt":
            from windows_job import OwnedJob
            self.job = OwnedJob()
        try:
            self.process = subprocess.Popen(argv, cwd=self.root, env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=flags | (0x4 if self.job else 0))  # suspended until in our job
            if self.job:
                self.job.assign_and_resume(self.process)
        except Exception:
            if self.process:
                self.process.kill()
            if self.job:
                self.job.close()
            raise
        self.status = "connecting"
        threading.Thread(target=self._reader, daemon=True).start()
        # Discard diagnostics: runtime logs can contain project/history data.
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        try:
            self.call("initialize", {"clientInfo": {"name": "chatgpt_local_bridge", "version": "1.0.0"},
                                     "capabilities": {"experimentalApi": True}})
            self._send({"method": "initialized", "params": {}})
            self.status = "connected"
            self.call("fs/watch", {"watchId": "bridge-project", "path": str(self.root)})
            profiles = self.call("permissionProfile/list", {})
            self.profile_available = any(p.get("id") == "bridge" and p.get("allowed") for p in profiles.get("data", []))
        except Exception:
            self.close()
            raise

    def _send(self, payload):
        with self.lock:
            if self.process is None or self.process.poll() is not None:
                raise BridgeError("RUNTIME_LOST: operation not replayed; inspect its result before retrying.")
            self.process.stdin.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            self.process.stdin.flush()

    def call(self, method: str, params: dict, timeout: float = 30):
        if method not in ALLOWED_METHODS:
            raise BridgeError("API_BLOCKED: this App Server method is not exported.")
        future = concurrent.futures.Future()
        with self.lock:
            self.sequence += 1
            request_id = self.sequence
            self.pending[request_id] = future
        try:
            self._send({"id": request_id, "method": method, "params": params})
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            # A timed-out request has an unknown result, not permission to retry it.
            raise BridgeError("RUNTIME_TIMEOUT: result unknown; operation was not replayed.") from exc
        finally:
            with self.lock:
                self.pending.pop(request_id, None)

    def _reader(self):
        try:
            for line in self.process.stdout:
                message = json.loads(line)
                if "method" in message and "id" in message:
                    self._send({"id": message["id"], "error": {"code": -32601,
                                "message": "Bridge does not approve permissions or model tool requests."}})
                elif "id" in message:
                    with self.lock:
                        future = self.pending.get(message["id"])
                    if future and not future.done():
                        if "error" in message:
                            error = message["error"]
                            # Full upstream errors are deliberately not exposed to remote callers.
                            self.last_rpc_error = str(error.get("message", ""))[:2000]
                            future.set_exception(BridgeError(f"RUNTIME_REJECTED: {error.get('code')}; capability refused."))
                        else:
                            future.set_result(message.get("result", {}))
                else:
                    for callback in tuple(self.listeners):
                        callback(message.get("method"), message.get("params", {}))
        except (OSError, ValueError, BrokenPipeError):
            pass
        finally:
            if self.job:
                self.job.close()
            self.status = "disconnected"
            self.command_ready = False
            self.error = "RUNTIME_LOST: operations are never automatically replayed."
            with self.lock:
                for future in self.pending.values():
                    if not future.done():
                        future.set_exception(BridgeError(self.error))

    def _drain_stderr(self):
        while self.process.stderr.read(8192):
            pass

    def command(self, argv, process_id, timeout, stream=True):
        if not self.command_ready:
            raise BridgeError("SANDBOX_UNAVAILABLE: " + self.command_error)
        try:
            return self.call("command/exec", {
                "command": list(argv), "cwd": str(self.root), "permissionProfile": "bridge",
                "processId": process_id, "timeoutMs": int(timeout * 1000),
                "streamStdoutStderr": stream, "outputBytesCap": 262144,
                "env": clean_environment(self.state / "cache"),
            }, timeout=timeout + 15)
        except BridgeError as exc:
            if str(exc).startswith("RUNTIME_TIMEOUT"):
                # Do not unlock project writes while a command's execution result is unknown.
                self.close()
            raise

    def verify_policy(self):
        """Canaries, not private user files. Refuse commands unless all checks pass."""
        token = uuid.uuid4().hex
        canary = self.state / ("outside-" + token + ".txt")
        script = self.state / "cache" / ("probe-" + token + ".py")
        canary.write_text("bridge-permission-canary", encoding="utf-8")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        script.write_text(
            "import os,pathlib,socket,json\n"
            "r={}\n"
            "try:\n pathlib.Path(" + repr(str(canary)) + ").read_bytes(); r['outside_blocked']=False\n"
            "except PermissionError: r['outside_blocked']=True\n"
            "try:\n s=socket.create_connection(('127.0.0.1'," + str(port) + "),2); s.close(); r['network_blocked']=False\n"
            "except OSError: r['network_blocked']=True\n"
            "r['key_absent']=not any(k for k in os.environ if any(x in k.upper() for x in ('API_KEY','TOKEN','SECRET','PASSWORD')))\n"
            "print(json.dumps(r))\n", encoding="utf-8")
        try:
            result = self.call("command/exec", {"command": [sys.executable, str(script)],
                "cwd": str(self.root), "permissionProfile": "bridge", "timeoutMs": 10000,
                "env": clean_environment(self.state / "cache")}, timeout=25)
            checks = json.loads(result.get("stdout", ""))
            self.probe_checks = checks
            self.command_ready = result.get("exitCode") == 0 and checks == {
                "outside_blocked": True, "network_blocked": True, "key_absent": True}
            failed = [name for name in ("outside_blocked", "network_blocked", "key_absent") if checks.get(name) is not True]
            self.command_error = "" if self.command_ready else "POLICY_CHECK_FAILED: " + ", ".join(failed) + "; no unsafe fallback."
        except (BridgeError, ValueError) as exc:
            if str(exc).startswith("RUNTIME_TIMEOUT"):
                self.close()
            self.command_ready = False
            self.command_error = "Windows refused the protected process or its canaries failed; no unsafe fallback."
        finally:
            listener.close()
            script.unlink(missing_ok=True)
            canary.unlink(missing_ok=True)
        return {"verified": self.command_ready, "error": self.command_error}

    def close(self):
        process = self.process
        if self.job:
            self.job.close()
        if process and process.poll() is None:
            if not self.job and os.name == "nt":
                # This PID is owned by this connection. Never target desktop processes by name.
                subprocess.run([str(Path(os.environ["SYSTEMROOT"]) / "System32/taskkill.exe"),
                                "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
            elif not self.job:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        self.status = "stopped"
        self.command_ready = False

"""Bridge capabilities. Every remote input is scoped here before an RPC."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid
from urllib.parse import urlparse

from files import (BridgeConfig, BridgeError, ChangeJournal, ProjectFiles, _bounded, _redact,
                   _sha256, check_link_chain, git_repository, integer, load_config)
from runtime import AppServer
from tasks import TaskRunner


class LocalBridge(ChangeJournal):
    def __init__(self, config, runtime=None, start_runtime=True):
        super().__init__(config)
        runtime_roots = [Path(sys.base_prefix), Path(sys.prefix), *config.runtime_read_roots]
        for exe in ("rg", "git"):
            resolved = shutil.which(exe)
            if resolved:
                parent = Path(resolved).resolve().parent
                runtime_roots.append(parent.parent if exe == "git" else parent)
        self.runtime = runtime or AppServer(self.root, self.state, config.codex_executable, runtime_roots)
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
        self.runtime.close()
        if run_id and not self.tasks.runs[run_id]["done"].wait(12):
            raise BridgeError("SHUTDOWN_TIMEOUT: journal remains locked until the bridge process exits.")
        self.close_journal()

    def _event(self, method, data):
        if method == "fs/changed" and data.get("watchId") == "bridge-project":
            # Only a counter reaches the UI; events may name protected paths.
            self.revision += 1

    def project_info(self):
        return {"workspace_root": self.root.as_posix(), "git_available": shutil.which("git") is not None,
                "git_repository": git_repository(self.root),
                "runtime": {"status": self.runtime.status, "version": self.runtime.version,
                            "error": self.runtime.error, "commands_enabled": self.runtime.command_ready,
                            "command_error": self.runtime.command_error},
                "capabilities": {"changes": True, "read_file": True, "control_panel": True,
                    "search": self.runtime.command_ready, "tasks": self.runtime.command_ready,
                    "watch": self.runtime.status == "connected", "skills": self.runtime.status == "connected",
                    "history": self.runtime.status == "connected", "docs": self.runtime.status == "connected"},
                "approved_tasks": list(self.config.tasks), "active_run_id": self.active_run,
                "revision": self.revision, "recovery_conflicts": [dict(r) for r in self.db.execute(
                    "SELECT id,error FROM changes WHERE status='recovery_conflict'")]}

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
        integer(max_results, "max_results", 1, 100)
        integer(cursor, "cursor", 0, 100000)
        integer(context_lines, "context_lines", 0, 5)
        if type(case_sensitive) is not bool:
            raise BridgeError("INVALID_INPUT: case_sensitive must be boolean.")
        types = file_types or []
        if not isinstance(types, list) or len(types) > 20 or any(not re.fullmatch(r"[A-Za-z0-9]{1,16}", t) for t in types):
            raise BridgeError("INVALID_INPUT: file_types must be extensions such as py or ts.")
        exe = shutil.which("rg")
        if not exe:
            raise BridgeError("UNSUPPORTED_CAPABILITY: rg.exe is not installed.")
        inventory = self.list_files(prefix, self.config.max_list_results)
        candidates = []
        for name in inventory["files"]:
            if types and Path(name).suffix.lstrip(".").lower() not in [t.lower() for t in types]:
                continue
            try:
                target, _ = self._file(name)
                if target.stat().st_size <= self.config.max_file_bytes:
                    candidates.append(name)
            except (BridgeError, OSError):
                continue
        results, seen, more, output_truncated = [], 0, False, False
        for offset in range(0, len(candidates), 40):
            argv = [exe, "--json", "--no-config", "--fixed-strings", "--line-number", "--no-heading",
                    "--no-mmap", "--max-filesize", str(self.config.max_file_bytes), "--color", "never"]
            if not case_sensitive:
                argv.append("--ignore-case")
            output = self._command_read(argv + ["--", query, *candidates[offset:offset+40]])
            if output.get("exitCode") not in (0,1):
                raise BridgeError("SEARCH_FAILED: runtime rejected the search; narrow the prefix.")
            output_truncated |= len(output.get("stdout", "").encode("utf-8")) >= 262144
            for line in output.get("stdout", "").splitlines():
                try:
                    event = json.loads(line)
                    if event.get("type") != "match":
                        continue
                    hit = event["data"]
                    path = hit["path"]["text"].removeprefix("./").replace("\\", "/")
                    _, path, data = self._read_bytes(path)
                    lines = data.decode("utf-8").splitlines()
                    number = hit["line_number"]
                    if number < 1 or number > len(lines):
                        continue
                    # Do not return stale rg content if another program changed the file.
                    actual = lines[number-1]
                    if (query if case_sensitive else query.casefold()) not in (actual if case_sensitive else actual.casefold()):
                        continue
                    if seen >= cursor:
                        if len(results) == max_results:
                            more = True
                            break
                        results.append({"path": path, "line": number, "text": _redact(actual),
                            "context_start_line": max(1,number-context_lines),
                            "context": _redact("\n".join(lines[max(0,number-context_lines-1):number+context_lines])),
                            "sha256": _sha256(data)})
                    seen += 1
                except (ValueError, KeyError, BridgeError):
                    continue
            if more:
                break
        return {"matches": results, "next_cursor": cursor+len(results) if more else None,
                "inventory_truncated": inventory["truncated"],
                "output_truncated": output_truncated,
                "hint": "Narrow prefix/query or use read_file if truncated; cursors apply to current file contents."}

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

    def show_control_panel(self):
        return {"panel_available":True, "project":self.project_info(),
                **self.list_changes(), "task_state":self.tasks.list_tasks()}

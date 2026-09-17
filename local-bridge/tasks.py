"""Configured tasks and paged logs, sharing the journal's mutation lock."""
import base64
import codecs
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import time
import uuid

from files import BridgeError, _bounded, _redact, integer, request_key


class TaskRunner:
    def __init__(self, owner, runtime):
        self.owner, self.runtime = owner, runtime
        self.runs = {}
        runtime.listeners.append(self._event)

    def list_tasks(self):
        available = self.runtime.can_execute
        return {"tasks": [{"task_id": name, "command": list(argv)} for name, argv in self.owner.config.tasks.items()],
                "available": available, "unavailable_reason": None if available else (self.runtime.command_error or None),
                "active_run_id": self.owner.active_run}

    def _command(self, task_id):
        argv = list(self.owner.config.tasks[task_id])
        if task_id == "git_diff_check":
            argv = [sys.executable, str(Path(__file__).with_name("git_diff_check.py"))]
        configured = Path(argv[0])
        exe = str(configured) if configured.is_absolute() and configured.is_file() else shutil.which(argv[0])
        if not exe or Path(exe).suffix.lower() in {".cmd", ".bat", ".ps1"}:
            raise BridgeError("TASK_UNAVAILABLE: configure the native executable and fixed arguments locally.")
        resolved = Path(exe).resolve()
        if resolved.is_relative_to(self.owner.root) and not any(
                resolved.is_relative_to(runtime_root) for runtime_root in self.owner.config.runtime_read_roots):
            raise BridgeError("TASK_UNAVAILABLE: the executable must be outside the project or in runtime_read_roots.")
        argv[0] = str(resolved)
        if resolved.stem.lower() == "git":
            argv[1:1] = ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath="+os.devnull,
                         "-c", "core.pager=cat"]
        return argv

    def start_task(self, task_id, request_id, timeout_seconds=120):
        request_key(request_id)
        integer(timeout_seconds, "timeout_seconds", 1, self.owner.config.max_task_timeout_seconds)
        if task_id not in self.owner.config.tasks:
            raise BridgeError("TASK_NOT_ALLOWED: use list_tasks for locally configured IDs.")
        with self.owner.lock:
            prior = self.owner.db.execute("SELECT * FROM runs WHERE request_id=?", (request_id,)).fetchone()
            if prior:
                if prior["task_id"] != task_id or prior["timeout"] != timeout_seconds:
                    raise BridgeError("IDEMPOTENCY_CONFLICT: request_id already used with another task or timeout.")
                return self.get_task_run(prior["id"])
            self.owner._idle()
            if not self.runtime.can_execute:
                raise BridgeError("SANDBOX_UNAVAILABLE: " + self.runtime.command_error)
            argv = self._command(task_id)
            self.owner.check_command_paths()
            run_id, now = uuid.uuid4().hex, time.time()
            with self.owner.db:
                self.owner.db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
                    (run_id,request_id,task_id,timeout_seconds,"running",now,None,None,None))
            self.runs[run_id] = {"events": [], "base": 0, "chars": 0, "truncated": False,
                "pending": {"stdout": "", "stderr": ""}, "decoders": {k: codecs.getincrementaldecoder("utf-8")("replace") for k in ("stdout","stderr")},
                "done": threading.Event(), "stop_reason": None, "command": argv}
            self.owner.active_run = run_id
            threading.Thread(target=self._work, args=(run_id,argv,timeout_seconds), daemon=True).start()
            return self.get_task_run(run_id)

    def _append(self, run, stream, text, final=False):
        pending = run["pending"][stream] + text
        if not final and "\n" in pending:
            emit, pending = pending.rsplit("\n", 1)
            emit += "\n"
        elif final:
            emit, pending = pending, ""
        else:
            emit = ""
        if len(pending) > 262144:
            pending = pending[:262144]
            run["truncated"] = True
        run["pending"][stream] = pending
        if emit:
            emit = _redact(emit)
            run["events"].append({"stream": stream, "text": emit})
            run["chars"] += len(emit)
            while run["chars"] > 262144 and len(run["events"]) > 1:
                run["chars"] -= len(run["events"].pop(0)["text"])
                run["base"] += 1
                run["truncated"] = True

    def _event(self, method, data):
        if method != "command/exec/outputDelta":
            return
        with self.owner.lock:
            run = self.runs.get(data.get("processId"))
            if not run:
                return
            stream = data.get("stream")
            if stream not in ("stdout", "stderr"):
                return
            try:
                raw = base64.b64decode(data["deltaBase64"], validate=True)
            except (ValueError, KeyError):
                run["truncated"] = True
                return
            self._append(run, stream, run["decoders"][stream].decode(raw))
            run["truncated"] |= bool(data.get("capReached"))

    def _work(self, run_id, argv, timeout):
        run = self.runs[run_id]
        timer = threading.Timer(timeout, self._timeout, args=(run_id,))
        timer.daemon = True
        timer.start()
        status, code, error = "failed", None, None
        try:
            # ponytail: Windows sandbox rejects streaming; buffer one bounded result and emit it on exit.
            streaming = os.name != "nt"
            result = self.runtime.command(argv, run_id, timeout, stream=streaming)
            if not streaming:
                with self.owner.lock:
                    for stream in ("stdout", "stderr"):
                        self._append(run, stream, result.get(stream) or "", final=True)
            code = result.get("exitCode")
            status = "succeeded" if code == 0 else "failed"
        except BridgeError as exc:
            status, error = "runtime_lost" if self.runtime.status != "connected" else "failed", str(exc)
        except Exception:
            status, error = "failed", "TASK_FAILED: local runtime rejected the task."
        finally:
            timer.cancel()
            with self.owner.lock:
                for stream in ("stdout", "stderr"):
                    self._append(run, stream, run["decoders"][stream].decode(b"", final=True), final=True)
                status = run["stop_reason"] or status
                with self.owner.db:
                    self.owner.db.execute("UPDATE runs SET status=?,ended=?,exit_code=?,error=? WHERE id=?",
                        (status,time.time(),code,error,run_id))
                if self.owner.active_run == run_id:
                    self.owner.active_run = None
                run["done"].set()
                # ponytail: in-memory logs for the latest 30 runs; persist logs only if cross-restart logs are needed.
                for old in list(self.runs)[:-30]:
                    if self.runs[old]["done"].is_set():
                        del self.runs[old]

    def _timeout(self, run_id):
        self.stop_task_run(run_id, "timeout-"+run_id, reason="timed_out")

    def stop_task_run(self, run_id, request_id, reason="stopped"):
        with self.owner.lock:
            replay = self.owner._operation(request_id, "stop", run_id)
            info = self.get_task_run(run_id)
            if replay or info["status"] != "running":
                return info
            with self.owner.db:
                self.owner.db.execute("INSERT INTO operations VALUES (?,?,?)", (request_id,"stop",run_id))
            run = self.runs[run_id]
            already_stopping = run["stop_reason"] is not None
            run["stop_reason"] = run["stop_reason"] or reason
        if not already_stopping:
            threading.Thread(target=self._terminate, args=(run_id,), daemon=True).start()
        return self.get_task_run(run_id)

    def _terminate(self, run_id):
        try:
            self.runtime.call("command/exec/terminate", {"processId": run_id}, timeout=8)
        except BridgeError:
            pass
        # Termination can race initial spawn. A closed owned job is the fail-safe for all its children.
        if not self.runs[run_id]["done"].wait(3):
            self.runtime.close()

    def get_task_run(self, run_id, cursor=0, max_events=100):
        integer(cursor, "cursor", 0, 2**31)
        integer(max_events, "max_events", 1, 200)
        with self.owner.lock:
            row = self.owner.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                raise BridgeError("NOT_FOUND: unknown run_id.")
            run = self.runs.get(run_id)
            start = max(cursor, run["base"]) if run else cursor
            events = run["events"][start-run["base"]:start-run["base"]+max_events] if run else []
            return {"run_id": run_id, "task_id": row["task_id"], "status": row["status"],
                "elapsed_seconds": round((row["ended"] or time.time())-row["started"], 2),
                "exit_code": row["exit_code"], "error": row["error"], "events": events,
                "next_cursor": start+len(events), "logs_available": run is not None,
                "truncated": (run["truncated"] or cursor < run["base"]) if run else True,
                "stopping": bool(run and run["stop_reason"] and not run["done"].is_set()),
                "timed_out": row["status"] == "timed_out"}

    def run_task(self, task_id, timeout_seconds=120):
        info = self.start_task(task_id, uuid.uuid4().hex, timeout_seconds)
        run = self.runs[info["run_id"]]
        run["done"].wait(timeout_seconds+30)
        info = self.get_task_run(info["run_id"], max_events=200)
        streams = {key: _bounded("".join(e["text"] for e in run["events"] if e["stream"] == key))[0] for key in ("stdout","stderr")}
        return {**info, **streams, "command": run["command"]}

"""Live, non-generating App Server acceptance checks on a disposable project."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from bridge import LocalBridge
from files import BridgeConfig, BridgeError


def verify_commands(b, root, checks):
    """Only entered after the real policy canaries pass; never force command_ready."""
    index=(root/".git/index").read_bytes()
    b.write_file("sample.txt","bridge-public-needle\r\n",b.read_file("sample.txt")["sha256"])
    (root/".env").write_text("bridge-private-needle modified\n",encoding="utf-8")
    assert b.search_code("bridge-public-needle")["matches"]
    assert not b.search_code("bridge-private-needle")["matches"]
    diff=b.git_diff()["diff"]
    assert "bridge-public-needle" in diff and "bridge-private-needle" not in diff
    assert (root/".git/index").read_bytes()==index
    checks["live_search_diff_privacy_and_git_index"]=True

    def completed(run_id):
        assert b.tasks.runs[run_id]["done"].wait(18),"Task did not terminate"
        return b.tasks.get_task_run(run_id)

    for task in ("git_status","git_diff_check"):
        result=completed(b.tasks.start_task(task,"verify-"+task,10)["run_id"])
        assert result["status"]=="succeeded"
    checks["live_configured_git_tasks"]=True

    for task,expected,code in (("sample_success","succeeded",0),("sample_failure","failed",7)):
        started=time.monotonic()
        run=b.tasks.start_task(task,"verify-"+task,10)["run_id"]
        assert time.monotonic()-started<2,"start_task waited for task completion"
        assert b.tasks.start_task(task,"verify-"+task,10)["run_id"]==run
        observed_live_log=False
        deadline=time.monotonic()+18
        while not b.tasks.runs[run]["done"].wait(.05) and time.monotonic()<deadline:
            observed_live_log |= bool(b.tasks.get_task_run(run)["events"])
        result=completed(run)
        assert result["status"]==expected and result["exit_code"]==code
        assert observed_live_log,"No log arrived while the task was running"
    assert (root/"build-output.txt").read_text()=="sample build output"
    checks["live_success_failure_build_stream_and_replay"]=True

    run=b.tasks.start_task("sample_slow","verify-timeout",1)["run_id"]
    assert completed(run)["status"]=="timed_out"
    checks["live_timeout"]=True

    run=b.tasks.start_task("sample_children","verify-stop-children",20)["run_id"]
    pidfile=root/"child.pid"
    deadline=time.monotonic()+10
    while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.05)
    child_pid=int(pidfile.read_text())
    change=b.prepare_changes("Writes stay locked",[{"path":"write-lock.txt","content":"new"}],"verify-write-lock")
    try:b.apply_changes(change["change_id"],"verify-write-lock-apply")
    except BridgeError as exc:assert str(exc).startswith("TASK_BUSY")
    else:raise AssertionError("Task did not lock writes")
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.OpenProcess(0x100000,False,child_pid)
    assert handle and kernel.WaitForSingleObject(handle,0)==258
    try:
        b.tasks.stop_task_run(run,"verify-stop-001")
        b.tasks.stop_task_run(run,"verify-stop-001")
        assert completed(run)["status"]=="stopped"
        assert kernel.WaitForSingleObject(handle,5000)==0,"A task child survived Stop"
    finally:kernel.CloseHandle(handle)
    checks["live_stop_descendants_and_write_lock"]=True


def main():
    base=Path(__file__).resolve().parent/".verification"
    base.mkdir(exist_ok=True)
    temp=Path(tempfile.mkdtemp(prefix="runtime-",dir=base)).resolve()
    assert temp.is_relative_to(base.resolve())
    root=temp/"project with spaces";root.mkdir()
    (root/"sample.txt").write_bytes("Khầy\r\nkiểm thử\r\n".encode())
    (root/".env").write_text("bridge-private-needle\n",encoding="utf-8")
    (root/"sample_task.py").write_text('''import pathlib,subprocess,sys,time
mode=sys.argv[1]
if mode=="children":
    child=subprocess.Popen([sys.executable,__file__,"slow"])
    pathlib.Path("child.pid").write_text(str(child.pid))
print("sample task started",flush=True)
if mode in ("children","slow"):
    while True:time.sleep(.2)
time.sleep(1)
if mode=="failure":
    print("expected fixture failure",file=sys.stderr,flush=True)
    sys.exit(7)
pathlib.Path("build-output.txt").write_text("sample build output")
print("sample task completed",flush=True)
''',encoding="utf-8")
    for args in (("init",),("add","sample.txt",".env")):
        subprocess.run([shutil.which("git"),*args],cwd=root,check=True,capture_output=True,
                       creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
    report={"project":str(root),"checks":{},"not_verified":[]}
    tasks={"git_status":("git","status","--short"),"git_diff_check":("git","diff","--check")}
    tasks.update({"sample_"+name:(sys.executable,"sample_task.py",name) for name in ("success","failure","slow","children")})
    b=LocalBridge(BridgeConfig(root,tasks,state_dir=temp/"state"))
    try:
        report["version"]=b.runtime.version
        report["commands_enabled"]=b.runtime.command_ready
        report["checks"]["stdio_initialized"]=b.runtime.status=="connected"
        report["checks"]["command_permission_canaries"]=getattr(b.runtime,"probe_checks",{})
        report["command_error"]=b.runtime.command_error
        target,relative=b._file("sample.txt")
        r=b.runtime.call("fs/readFile",{"path":str(target)})
        assert base64.b64decode(r["dataBase64"])==target.read_bytes()
        report["checks"]["app_server_filesystem_read"]=True
        r=b.read_file(relative,2,end_line=2)
        assert r["content"]=="kiểm thử\r\n"
        report["checks"]["bridge_read_lines"]=True
        revision=b.revision
        b.write_file("watch.txt","watch event")
        deadline=time.monotonic()+5
        while b.revision==revision and time.monotonic()<deadline:
            time.sleep(.05)
        report["checks"]["filesystem_watch"]=b.revision>revision
        skills=b.list_skills()
        report["checks"]["skills_list"]=bool(skills["skills"])
        if skills["skills"]:
            skill=b.read_skill(skills["skills"][0]["skill_id"])
            report["checks"]["skill_read"]=bool(skill["content"])
        report["checks"]["project_history_scope"]=b.list_codex_threads()["threads"]==[]
        docs=b.codex_docs_fetch("https://developers.openai.com/apps-sdk/build/mcp-server/")
        report["checks"]["docs_fetch"]=bool(docs["result"].get("content"))
        docs=b.codex_docs_search("MCP Apps UI",limit=1)
        report["checks"]["docs_search"]=bool(docs["result"].get("content"))
        servers=b.runtime.call("mcpServerStatus/list",{"limit":100})
        enabled={s["name"]:list(s.get("tools",{})) for s in servers.get("data",[]) if s.get("tools")}
        report["checks"]["only_approved_mcp_tools"]=(set(enabled)=={"openaiDeveloperDocs"} and
            set(enabled["openaiDeveloperDocs"])=={"search_openai_docs","fetch_openai_doc"})
        report["callable_mcp_tools"]=enabled
        if not b.runtime.command_ready:
            try:b.tasks.start_task("git_status","verify-start-task")
            except BridgeError as e:report["checks"]["task_fails_closed"]=str(e).startswith("SANDBOX_UNAVAILABLE")
            else:raise AssertionError("Unprotected task was allowed")
            report["not_verified"] += ["Live protected test/build, streaming, timeout and descendant termination", "Live rg and Git diff through App Server"]
        else:
            verify_commands(b,root,report["checks"])
        report["scope_note"]="This script checks App Server only; ChatGPT UI has separate evidence."
    except Exception as exc:
        report["error"]=str(exc)
        raise
    finally:
        b.close()
        output=base/"runtime-result.json"
        output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
        print(json.dumps(report,ensure_ascii=False,indent=2))
        print("Evidence:",output)
    return 0 if report.get("commands_enabled") and not report["not_verified"] else 2


if __name__=="__main__":
    raise SystemExit(main())

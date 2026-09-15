"""Live Turbo and workspace switching checks; only synthetic project data is used."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from files import BridgeError
from session import WorkspaceSession


def readable_canary(path):
    path.write_text("synthetic outside read", encoding="utf-8")
    # Ambient Windows reads do not override a file's ACL. Grant only this fake
    # test file read access; do not alter permissions on any private user data.
    subprocess.run(["icacls",str(path),"/grant","*S-1-1-0:R"],check=True,capture_output=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)


def completed(bridge, run):
    assert bridge.tasks.runs[run["run_id"]]["done"].wait(35), "Command did not finish"
    result = bridge.tasks.get_task_run(run["run_id"], max_events=200)
    assert result["status"] == "succeeded", result
    return "".join(e["text"] for e in result["events"] if e["stream"] == "stdout")


def main():
    base = Path(__file__).resolve().parent / ".verification"
    home = Path(tempfile.mkdtemp(prefix="turbo-", dir=base)).resolve()
    roots = [home / name for name in ("project one", "project two")]
    for root in roots:
        root.mkdir()
    outside = home / "outside.txt"
    readable_canary(outside)
    config = home / "config.json"
    config.write_text(json.dumps({"workspace_root":str(roots[0]), "state_dir":str(home / "state"),
                                  "tasks":{"git_status":["git","status","--short"]}}))
    report = {"project":str(roots[0]), "second_project":str(roots[1]), "outside_read_scope":"ambient Windows ACL; synthetic canary explicitly readable", "checks":{}}
    session = WorkspaceSession(config)
    try:
        assert session.current.runtime.command_ready, session.info()
        try:
            session.current.tasks.execute_command([sys.executable, "-c", "print('must not run')"], "normal-deny-command")
        except BridgeError as exc:
            assert str(exc).startswith("MODE_REQUIRED")
        else:
            raise AssertionError("Normal allowed arbitrary commands")
        report["checks"]["normal_rejects_arbitrary_commands"] = True
        session.switch(session.context_id, mode="turbo")
        b = session.current
        assert b.runtime.command_ready, session.info()
        report["version"] = b.runtime.version
        report["checks"]["turbo_canaries"] = b.runtime.probe_checks
        owner_only = home/"owner-read.txt"
        owner_only.write_text("read outside through file tool")
        assert b.read_file(str(owner_only))["content"] == "read outside through file tool"
        report["checks"]["absolute_external_file_read"] = True
        quote = shlex.quote
        script = "mkdir -p work\nprintf 'print(\"script-created-and-executed\")\\n' > work/generated.py\n" + quote(sys.executable.replace("\\", "/")) + " -I work/generated.py\n"
        result = completed(b, b.run_bash(script, "turbo-bash-script", 20))
        assert "script-created-and-executed" in result
        assert (roots[0] / "work/generated.py").is_file()
        report["checks"]["bash_creates_and_runs_script"] = True
        probe = '''import json,os,pathlib,socket,sys
p=pathlib.Path(sys.argv[1]); root=pathlib.Path.cwd(); checks={}
checks['outside_read_allowed']=p.read_text()=='synthetic outside read'
for action in ('write','delete','create'):
    try:
        if action=='write': p.write_text('forbidden')
        elif action=='delete': p.unlink()
        else: p.with_name('outside-created.txt').write_text('forbidden')
        checks['outside_'+action+'_blocked']=False
    except PermissionError: checks['outside_'+action+'_blocked']=True
checks['cache_inside_project']=pathlib.Path(os.environ['TEMP']).resolve().is_relative_to(root)
checks['key_absent']=not any(any(x in k.upper() for x in ('API_KEY','TOKEN','SECRET','PASSWORD')) for k in os.environ)
with socket.create_connection(('1.1.1.1',443),5): checks['external_network_allowed']=True
print(json.dumps(checks),flush=True)
sys.exit(0 if all(checks.values()) else 1)
'''
        result = completed(b, b.tasks.execute_command([sys.executable, "-I", "-c", probe, str(outside)], "turbo-permission-probe", 20))
        report["checks"]["script_permissions"] = json.loads(result)
        assert all(report["checks"]["script_permissions"].values())
        bash_probe = "if printf 'forbidden' > " + quote(outside.as_posix()) + "; then exit 7; else printf 'bash-outside-write-blocked\\n'; fi"
        assert "bash-outside-write-blocked" in completed(b, b.run_bash(bash_probe, "turbo-bash-outside", 20))
        assert outside.read_text() == "synthetic outside read"
        report["checks"]["bash_outside_write_blocked"] = True
        skills = b.list_skills()["skills"]
        assert skills and all(s.get("directory") for s in skills)
        assert b.read_skill(skills[0]["skill_id"])["content"]
        report["skill_count"] = len(skills)
        report["checks"]["turbo_skills"] = True
        tools = b.list_mcp_tools(server_name="openaiDeveloperDocs", limit=50)
        report["mcp_servers"] = tools["servers"]
        docs = next(t for t in tools["tools"] if t["name"] == "search_openai_docs")
        result = b.call_mcp_tool(docs["tool_id"], {"query":"Codex permission profiles", "limit":1}, "turbo-live-mcp-call")
        assert result["result"].get("content") and not result["result"].get("isError")
        assert result == b.call_mcp_tool(docs["tool_id"], {"query":"Codex permission profiles", "limit":1}, "turbo-live-mcp-call")
        report["checks"]["turbo_mcp_call_and_deduplication"] = True
        node_tools = b.list_mcp_tools(server_name="node_repl")["tools"]
        javascript = next(t for t in node_tools if t["name"] == "js")
        result = b.call_mcp_tool(javascript["tool_id"], {"code":"nodeRepl.write('bridge-existing-mcp-ok')", "title":"Verify existing Codex MCP"}, "turbo-existing-mcp")
        assert not result["result"].get("isError") and "bridge-existing-mcp-ok" in json.dumps(result), result
        report["checks"]["existing_codex_node_mcp"] = True
        change = b.prepare_changes("First project only", [{"path":"selected-only.txt", "content":"first root"}], "turbo-root-change")
        old_context = session.context_id
        session.switch(old_context, workspace_root=str(roots[1]))
        assert session.current.runtime.command_ready, session.info()
        try:
            with session.use(old_context, require_context=True):
                raise AssertionError("Stale context was accepted")
        except BridgeError as exc:
            assert str(exc).startswith("CONTEXT_CHANGED")
        try:
            session.current.apply_changes(change["change_id"], "turbo-wrong-project")
        except BridgeError as exc:
            assert str(exc).startswith("NOT_FOUND")
        else:
            raise AssertionError("First project's change was applied to the second")
        old_file = roots[0] / "old-project.txt"
        readable_canary(old_file)
        result = completed(session.current, session.current.tasks.execute_command(
            [sys.executable,"-I","-c",probe,str(old_file)], "turbo-old-root-write",20))
        assert all(json.loads(result).values()), result
        assert old_file.read_text() == "synthetic outside read"
        report["checks"]["switch_revokes_old_project_writes"] = True
        session.switch(session.context_id, workspace_root=str(roots[0]))
        session.current.apply_changes(change["change_id"], "turbo-right-project")
        session.current.undo_changes(change["change_id"], "turbo-right-project-undo")
        assert not (roots[0]/"selected-only.txt").exists() and not (roots[1]/"selected-only.txt").exists()
        report["checks"]["per_project_journals_and_stale_context"] = True
        session.switch(session.context_id, mode="normal")
        assert session.current.runtime.command_ready
        report["checks"]["normal_restored"] = True
    except Exception as exc:
        report["error"] = str(exc)
        report["runtime_error"] = getattr(session.current.runtime,"last_rpc_error",None)
        raise
    finally:
        session.close()
        output = base / "turbo-result.json"
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print("Evidence:", output)


if __name__ == "__main__":
    main()

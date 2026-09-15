"""Run: uv run --with mcp==1.30.0 --python 3.13 server.py --self-test."""
import asyncio
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from bridge import LocalBridge
from files import BridgeConfig, BridgeError, ChangeJournal, _sha256, load_config
from runtime import ALLOWED_METHODS, AppServer, clean_environment, process_overrides
from session import WorkspaceSession


class FakeRuntime:
    """Deterministic protocol peer. These checks do not certify an OS sandbox."""
    def __init__(self, root):
        self.root=root
        self.listeners=[]
        self.command_ready=True
        self.command_error=""
        self.status="connected"
        self.version="test-peer"
        self.error=None
        self.calls=[]
        self.release=threading.Event()

    def command(self, argv, process_id, timeout, stream=True):
        self.calls.append(("command/exec",argv))
        if Path(argv[0]).stem.lower() in ("git","rg"):
            r=subprocess.run(argv,cwd=self.root,capture_output=True,encoding="utf-8",errors="replace",timeout=10)
            return {"exitCode":r.returncode,"stdout":r.stdout,"stderr":r.stderr}
        for raw in (b"First line\n",b"token=do-not-",b"leak\n"):
            for listener in self.listeners:
                listener("command/exec/outputDelta",{"processId":process_id,"stream":"stdout","deltaBase64":base64.b64encode(raw).decode(),"capReached":False})
        self.release.wait(2)
        return {"exitCode":0,"stdout":"","stderr":""}

    def call(self, method, params, timeout=30):
        self.calls.append((method,params))
        if method == "command/exec/terminate":
            self.release.set()
            return {}
        if method == "thread/read":
            return {"thread":{"cwd":str(self.root),"turns":[{"id":"turn1","items":[{"type":"agentMessage","text":"hello"},{"type":"commandExecution","output":"private"}]}]}}
        raise BridgeError("test peer: unsupported method")

    def close(self):
        self.release.set()
        self.status="stopped"

    def terminate(self, process_id):
        return self.call("command/exec/terminate", {"processId":process_id})


class BridgeTests(unittest.TestCase):
    def setUp(self):
        base=Path(__file__).resolve().parent/".verification"
        base.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix="test-",dir=base)
        self.home=Path(self.temp.name).resolve()
        assert self.home.is_relative_to(base.resolve())
        self.root=self.home/"project with spaces"
        self.root.mkdir()
        self.config=BridgeConfig(self.root,{"sample_test":(sys.executable,"sample.py")},state_dir=self.home/"state")
        self.runtime=FakeRuntime(self.root)
        self.b=LocalBridge(self.config,self.runtime)

    def tearDown(self):
        self.b.close()
        self.temp.cleanup()

    def change(self, edits, key="prepare-001"):
        return self.b.prepare_changes("Thay đổi tiếng Việt",edits,key)["change_id"]

    def test_preview_apply_undo_crlf_and_dirty_content(self):
        original="Khầy\r\nlocal dirty edit\r\n".encode()
        (self.root/"a.txt").write_bytes(original)
        (self.root/"unrelated.txt").write_bytes(b"keep me")
        c=self.change([{"path":"a.txt","content":"mới\r\n","expected_sha256":_sha256(original)},
                       {"path":"xin chao.txt","content":"tạo mới\r\n"}])
        self.assertEqual((self.root/"a.txt").read_bytes(),original)
        self.assertFalse((self.root/"xin chao.txt").exists())
        self.assertIn("local dirty edit",self.b.get_change(c)["diff"])
        self.b.apply_changes(c,"apply-001")
        self.assertEqual((self.root/"a.txt").read_bytes(),"mới\r\n".encode())
        self.b.undo_changes(c,"undo-001")
        self.assertEqual((self.root/"a.txt").read_bytes(),original)
        self.assertFalse((self.root/"xin chao.txt").exists())
        self.assertEqual((self.root/"unrelated.txt").read_bytes(),b"keep me")

    def test_sha_conflict_refuses_whole_batch(self):
        for name in ("a.txt","b.txt"):(self.root/name).write_bytes(b"old")
        c=self.change([{"path":n,"content":"new","expected_sha256":_sha256(b"old")} for n in ("a.txt","b.txt")])
        (self.root/"b.txt").write_bytes(b"outside edit")
        with self.assertRaisesRegex(BridgeError,"SHA_CONFLICT"):self.b.apply_changes(c,"apply-001")
        self.assertEqual((self.root/"a.txt").read_bytes(),b"old")
        (self.root/"b.txt").write_bytes(b"old")
        self.b.apply_changes(c,"apply-002")
        (self.root/"b.txt").write_bytes(b"another edit")
        with self.assertRaisesRegex(BridgeError,"SHA_CONFLICT"):self.b.undo_changes(c,"undo-001")
        self.assertEqual((self.root/"a.txt").read_bytes(),b"new")

    def test_idempotency_and_no_double_apply(self):
        edits=[{"path":"a.txt","content":"new"}]
        c=self.change(edits)
        self.assertEqual(c,self.change(edits))
        with self.assertRaisesRegex(BridgeError,"IDEMPOTENCY_CONFLICT"):self.change([{"path":"a.txt","content":"different"}])
        self.b.apply_changes(c,"apply-001")
        self.assertEqual(self.b.apply_changes(c,"apply-001")["status"],"applied")
        with self.assertRaisesRegex(BridgeError,"CHANGE_STATE"):self.b.apply_changes(c,"apply-002")
        with self.assertRaisesRegex(BridgeError,"IDEMPOTENCY_CONFLICT"):self.b.undo_changes(c,"apply-001")

    def test_exact_patch_and_legacy_history(self):
        (self.root/"a.txt").write_bytes(b"hello hello")
        for old in ("", "hello", "missing"):
            with self.assertRaisesRegex(BridgeError,"PATCH_AMBIGUOUS"):
                self.b.apply_patch("a.txt",old,"bye",_sha256(b"hello hello"))
        result=self.b.apply_patch("a.txt","hello hello","bye",_sha256(b"hello hello"))
        self.assertEqual(result["sha256"],_sha256(b"bye"))
        self.b.undo_changes(result["change_id"],"undo-001")
        self.assertEqual((self.root/"a.txt").read_bytes(),b"hello hello")
        with self.assertRaisesRegex(BridgeError,"SHA_CONFLICT"):self.b.write_file("a.txt","x",None)

    def test_path_binary_hardlink_guards(self):
        for path in ("../a", "C:/a", "a:stream", "a/../b", ".env", "config.env", "foo/.env.local", "x.key",
                     "NUL.txt", "a. ", "a.", "//server/a", "a//b", ".git/config", ".codex/config.toml"):
            with self.subTest(path=path),self.assertRaises(BridgeError):self.b.write_file(path,"blocked")
        (self.root/"binary.txt").write_bytes(b"\x00bad")
        with self.assertRaisesRegex(BridgeError,"BINARY_BLOCKED"):self.b.read_file("binary.txt")
        outside=self.home/"outside.txt";outside.write_bytes(b"private")
        os.link(outside,self.root/"hardlink.txt")
        with self.assertRaisesRegex(BridgeError,"PATH_BLOCKED"):self.b.read_file("hardlink.txt")
        self.assertNotIn("hardlink.txt",self.b.list_files()["files"])
        with self.assertRaisesRegex(BridgeError,"PATH_BLOCKED"):self.b.check_command_paths()
        if os.name=="nt":
            junction=self.root/"junction";destination=self.home/"outside-directory"
            destination.mkdir();(destination/"canary.txt").write_bytes(b"outside")
            subprocess.run([str(Path(os.environ["SYSTEMROOT"])/"System32/cmd.exe"),"/d","/c","mklink","/J",str(junction),str(destination)],
                check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                with self.assertRaisesRegex(BridgeError,"PATH_BLOCKED"):self.b.read_file("junction/canary.txt")
                self.assertNotIn("junction/canary.txt",self.b.list_files()["files"])
            finally:
                assert junction.parent==self.root and junction.is_junction()
                os.rmdir(junction)

    def test_read_lines_and_hash(self):
        data="một\r\nhai\r\nba\r\n".encode();(self.root/"a.txt").write_bytes(data)
        r=self.b.read_file("a.txt",2,end_line=2)
        self.assertEqual((r["content"],r["total_lines"],r["next_line"]),("hai\r\n",3,3))
        self.assertEqual(r["sha256"],_sha256(data))
        self.assertTrue(self.b.read_file("a.txt",max_bytes=5)["truncated"])

    def test_partial_write_recovers(self):
        c=self.change([{"path":"a.txt","content":"a"},{"path":"b.txt","content":"b"}])
        atomic=self.b._atomic_write;calls=0
        def fail_second(*args):
            nonlocal calls
            calls+=1
            if calls==2:raise OSError("disk fault")
            return atomic(*args)
        self.b._atomic_write=fail_second
        with self.assertRaisesRegex(BridgeError,"WRITE_FAILED"):self.b.apply_changes(c,"apply-001")
        self.assertEqual(self.b.get_change(c)["status"],"recovered")
        self.assertFalse((self.root/"a.txt").exists())
        self.assertFalse((self.root/"b.txt").exists())

    def test_restart_recovers_and_preserves_external_edit(self):
        c=self.change([{"path":"a.txt","content":"a"},{"path":"b.txt","content":"b"}])
        self.b._set_status(c,"applying")
        with self.b.db:
            self.b.db.execute("UPDATE files SET phase='writing' WHERE change_id=? AND path='a.txt'", (c,))
        (self.root/"a.txt").write_bytes(b"a")
        (self.root/"b.txt").write_bytes(b"someone else's edit")
        self.b.close();self.b=LocalBridge(self.config,FakeRuntime(self.root))
        self.assertFalse((self.root/"a.txt").exists())
        self.assertEqual((self.root/"b.txt").read_bytes(),b"someone else's edit")
        self.assertEqual(self.b.get_change(c)["status"],"recovery_conflict")
        other=self.change([{"path":"c.txt","content":"c"}],"prepare-002")
        with self.assertRaisesRegex(BridgeError,"RECOVERY_CONFLICT"):self.b.apply_changes(other,"apply-002")

    def test_recovery_does_not_revert_unattempted_matching_content(self):
        c=self.change([{"path":"a.txt","content":"planned"}])
        self.b._set_status(c,"applying")
        (self.root/"a.txt").write_bytes(b"planned")
        self.b.recover()
        self.assertEqual((self.root/"a.txt").read_bytes(),b"planned")
        self.assertEqual(self.b.get_change(c)["status"],"recovery_conflict")

    def test_legacy_retry_after_undo_does_not_claim_a_new_write(self):
        r=self.b.write_file("a.txt","new")
        self.b.undo_changes(r["change_id"],"undo-legacy")
        with self.assertRaisesRegex(BridgeError,"CHANGE_STATE"):self.b.write_file("a.txt","new")
        self.assertFalse((self.root/"a.txt").exists())

    def test_interrupted_undo_recovers_in_the_right_direction(self):
        for n in ("a.txt","b.txt"):(self.root/n).write_bytes(b"old")
        c=self.change([{"path":n,"content":"new","expected_sha256":_sha256(b"old")} for n in ("a.txt","b.txt")])
        self.b.apply_changes(c,"apply-001")
        atomic=self.b._atomic_write;count=0
        def crash_second(*args):
            nonlocal count
            count+=1
            if count==2:raise KeyboardInterrupt("simulated crash")
            atomic(*args)
        self.b._atomic_write=crash_second
        with self.assertRaises(KeyboardInterrupt):self.b.undo_changes(c,"undo-001")
        self.b._atomic_write=atomic
        (self.root/"b.txt").write_bytes(b"external")
        self.b.recover()
        self.assertEqual((self.root/"a.txt").read_bytes(),b"new")
        self.assertEqual((self.root/"b.txt").read_bytes(),b"external")
        self.assertEqual(self.b.get_change(c)["status"],"recovery_conflict")
        (self.root/"b.txt").write_bytes(b"new")  # local user resolves this fixture's conflict
        self.b.recover()
        self.assertEqual(self.b.get_change(c)["status"],"undo_failed")

    def test_retention_and_failure_preservation(self):
        self.b.config=replace(self.config,completed_changes_to_keep=2)
        failed=self.change([{"path":"fail.txt","content":"keep"}],"prepare-fail")
        self.b._set_status(failed,"recovered")
        ids=[]
        for i in range(3):
            c=self.change([{"path":f"a{i}.txt","content":"x"}],f"prepare-{i:03d}")
            self.b.apply_changes(c,f"apply-{i:03d}");ids.append(c)
        self.assertEqual(self.b.get_change(ids[0])["status"],"expired")
        self.assertEqual(self.b.get_change(failed)["status"],"recovered")
        self.assertEqual(len(self.b.get_change(failed)["files"]),1)

    def test_task_stream_stop_busy_replay(self):
        c=self.change([{"path":"a.txt","content":"a"}])
        info=self.b.tasks.start_task("sample_test","start-001",10)
        run=info["run_id"]
        self.assertEqual(run,self.b.tasks.start_task("sample_test","start-001",10)["run_id"])
        with self.assertRaisesRegex(BridgeError,"TASK_BUSY"):self.b.apply_changes(c,"apply-001")
        with self.assertRaisesRegex(BridgeError,"TASK_BUSY"):self.b.tasks.start_task("sample_test","start-002")
        self.b.tasks.stop_task_run(run,"stop-001")
        self.b.tasks.stop_task_run(run,"stop-001")
        self.assertTrue(self.b.tasks.runs[run]["done"].wait(4))
        result=self.b.tasks.get_task_run(run)
        self.assertEqual(result["status"],"stopped")
        text=json.dumps(result)
        self.assertNotIn("do-not-",text);self.assertIn("REDACTED",text)
        logs=self.b.tasks.runs[run]
        self.b.tasks._append(logs,"stdout","x"*300000+"\n")
        self.assertLessEqual(logs["chars"],262144)
        self.assertTrue(logs["truncated"])
        self.assertEqual(len([m for m,_ in self.runtime.calls if m=="command/exec"]),1)
        self.b.apply_changes(c,"apply-001")

    def test_timeout_and_runtime_fail_closed(self):
        self.runtime.command_ready=False
        with self.assertRaisesRegex(BridgeError,"SANDBOX_UNAVAILABLE"):self.b.tasks.start_task("sample_test","start-001")
        with self.assertRaisesRegex(BridgeError,"TASK_NOT_ALLOWED"):self.b.tasks.start_task("arbitrary","start-002")
        self.runtime.command_ready=True
        run=self.b.tasks.start_task("sample_test","start-003",1)["run_id"]
        self.assertTrue(self.b.tasks.runs[run]["done"].wait(4))
        self.assertEqual(self.b.tasks.get_task_run(run)["status"],"timed_out")

    def test_task_failure_and_runtime_loss_are_not_replayed(self):
        calls=[]
        def command(argv, process_id, timeout, stream=True):
            calls.append(process_id)
            if len(calls)==1:return {"exitCode":2}
            self.runtime.status="disconnected"
            raise BridgeError("RUNTIME_LOST: not replayed")
        self.runtime.command=command
        for request,status in (("failure-001","failed"),("lost-run-001","runtime_lost")):
            run=self.b.tasks.start_task("sample_test",request)["run_id"]
            self.assertTrue(self.b.tasks.runs[run]["done"].wait(4))
            self.assertEqual(self.b.tasks.get_task_run(run)["status"],status)
            self.assertEqual(self.b.tasks.start_task("sample_test",request)["run_id"],run)
        self.assertEqual(len(calls),2)

    def test_command_timeout_closes_owned_runtime(self):
        runtime=AppServer(self.root,self.home/"state")
        runtime.command_ready=True
        def rejected(method,params,**kwargs):
            self.assertNotIn("outputBytesCap",params)
            self.assertEqual(params["permissionProfile"],"bridge")
            raise BridgeError("RUNTIME_TIMEOUT: result unknown")
        runtime.call=rejected
        with self.assertRaisesRegex(BridgeError,"RUNTIME_TIMEOUT"):
            runtime.command([sys.executable],"unknown-run",1,stream=False)
        self.assertFalse(runtime.command_ready)
        self.assertEqual(runtime.status,"stopped")

    @unittest.skipUnless(os.name=="nt","Windows Job Object check")
    def test_owned_job_stops_descendants_only(self):
        import ctypes
        from ctypes import wintypes
        from windows_job import OwnedJob
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        kernel.OpenProcess.restype=wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        pidfile=self.home/"child.pid"
        program=("import subprocess,sys,time,pathlib; "
                 "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); "
                 "pathlib.Path(sys.argv[1]).write_text(str(child.pid));time.sleep(60)")
        job=OwnedJob();parent=None;child_handle=None
        unrelated=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            parent=subprocess.Popen([sys.executable,"-c",program,str(pidfile)],
                creationflags=subprocess.CREATE_NO_WINDOW|0x4,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            job.assign_and_resume(parent)
            deadline=time.monotonic()+5
            while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.05)
            child_handle=kernel.OpenProcess(0x100000,False,int(pidfile.read_text()))
            self.assertTrue(child_handle)
            self.assertEqual(kernel.WaitForSingleObject(child_handle,0),258)
            job.close();parent.wait(timeout=5)
            self.assertEqual(kernel.WaitForSingleObject(child_handle,5000),0)
            self.assertIsNone(unrelated.poll())
        finally:
            job.close()
            if parent and parent.poll() is None:parent.kill();parent.wait(timeout=5)
            if child_handle:kernel.CloseHandle(child_handle)
            unrelated.terminate();unrelated.wait(timeout=5)

    def test_search_filters_and_continuation(self):
        (self.root/"a file.txt").write_text("Khầy\nKhầy hai\nKhầy ba\n",encoding="utf-8")
        (self.root/".env").write_text("Khầy PRIVATE",encoding="utf-8")
        r=self.b.search_code("Khầy",max_results=1)
        self.assertEqual(r["matches"][0]["line"],1)
        self.assertEqual(r["next_cursor"],1)
        r=self.b.search_code("khầy",case_sensitive=False,cursor=1,max_results=1,file_types=["txt"])
        self.assertEqual(r["matches"][0]["line"],2)
        self.assertNotIn("PRIVATE",json.dumps(r))

    def test_git_diff_excludes_sensitive_files_and_preserves_index(self):
        def git(*args):
            return subprocess.run([shutil.which("git"),*args],cwd=self.root,capture_output=True,check=True)
        git("init")
        (self.root/"a.txt").write_text("old\n")
        (self.root/".env").write_text("PRIVATE OLD\n")
        git("add","a.txt",".env")
        index=(self.root/".git/index").read_bytes()
        (self.root/"a.txt").write_text("new\n")
        (self.root/".env").write_text("PRIVATE NEW\n")
        diff=self.b.git_diff()["diff"]
        self.assertIn("new",diff);self.assertNotIn("PRIVATE",diff)
        self.assertEqual((self.root/".git/index").read_bytes(),index)

    def test_scoped_history_skill_docs_and_no_model_api(self):
        with self.assertRaisesRegex(BridgeError,"SCOPE_DENIED"):self.b.read_codex_thread("outside")
        with self.assertRaisesRegex(BridgeError,"SCOPE_DENIED"):self.b.read_skill("invented")
        with self.assertRaisesRegex(BridgeError,"SCOPE_DENIED"):self.b.codex_docs_fetch("https://evil.example/a")
        self.b.known_threads.add("project-thread")
        history=self.b.read_codex_thread("project-thread")
        self.assertNotIn("private",json.dumps(history["turns"]))
        self.assertFalse(ALLOWED_METHODS & {"turn/start","review/start","thread/resume","thread/shellCommand","process/spawn","config/value/write"})
        skill=self.home/"skill";skill.mkdir();(skill/"SKILL.md").write_text("instructions")
        self.b.skills["known"]={"path":skill/"SKILL.md"}
        self.assertEqual(self.b.read_skill("known")["content"],"instructions")
        with self.assertRaises(BridgeError):self.b.read_skill_resource("known","../outside")

    def test_environment_and_config_boundary(self):
        self.assertFalse(self.b.project_info()["git_repository"])
        overrides=process_overrides(self.root,self.home/"cache",[])
        self.assertIn("features.plugins=false",overrides)
        self.assertIn("features.hooks=false",overrides)
        self.assertIn("permissions.bridge.network.enabled=true",overrides)
        self.assertIn("features.network_proxy=false",overrides)
        for name in ("USERNAME","USERDOMAIN"):
            if name in os.environ:
                self.assertEqual(clean_environment(self.home)[name],os.environ[name])
        filesystem=next(v for v in overrides if v.startswith("permissions.bridge.filesystem="))
        self.assertNotIn(json.dumps(str(self.root/".git"))+"=",filesystem)
        (self.root/".git").mkdir()
        self.assertFalse(self.b.project_info()["git_repository"])
        prior=os.environ.get("CONTROL_PLANE_API_KEY")
        try:
            os.environ["CONTROL_PLANE_API_KEY"]="DO_NOT_PASS"
            self.assertNotIn("CONTROL_PLANE_API_KEY",clean_environment(self.home))
        finally:
            if prior is None:os.environ.pop("CONTROL_PLANE_API_KEY",None)
            else:os.environ["CONTROL_PLANE_API_KEY"]=prior
        config=self.home/"bad-config.json"
        config.write_text(json.dumps({"workspace_root":str(self.root),"state_dir":str(self.root/"state")}))
        with self.assertRaises(BridgeError):load_config(config)

    def test_mcp_schema_and_ui_contract(self):
        import server
        tools=asyncio.run(server.mcp.list_tools())
        self.assertEqual(len(tools),31)
        linked=[t.name for t in tools if (t.meta or {}).get("ui",{}).get("resourceUri")]
        self.assertEqual(linked,["show_control_panel"])
        self.runtime.command_ready=False
        panel=self.b.show_control_panel()
        self.assertTrue(panel["panel_available"])
        self.assertFalse(panel["task_state"]["available"])
        names={t.name:t for t in tools}
        self.assertEqual(list(names["run_task"].inputSchema["properties"]),["task_id","timeout_seconds","context_id"])
        for name in ("set_runtime_mode", "select_workspace"):
            self.assertEqual(names[name].meta["ui"]["visibility"], ["app"])
        self.assertTrue(all(t.annotations and t.outputSchema for t in tools))
        contents=list(asyncio.run(server.mcp.read_resource(server.UI_URI)))
        self.assertEqual(contents[0].mime_type,"text/html;profile=mcp-app")
        html=contents[0].content
        for required in ("ui/initialize","ui/notifications/initialized","tools/call","ui/notifications/tool-result","2000"):
            self.assertIn(required,html)
        for unsafe in ("innerHTML","eval(","http://localhost","<script src="):
            self.assertNotIn(unsafe,html)

    def test_turbo_command_gate_and_replay(self):
        command=[sys.executable,"-c","print('turbo')"]
        with self.assertRaisesRegex(BridgeError,"MODE_REQUIRED"):
            self.b.tasks.execute_command(command,"turbo-command-1")
        self.b.config=replace(self.config,mode="turbo")
        first=self.b.tasks.execute_command(command,"turbo-command-1")
        self.assertEqual(first["run_id"],self.b.tasks.execute_command(command,"turbo-command-1")["run_id"])
        with self.assertRaisesRegex(BridgeError,"IDEMPOTENCY_CONFLICT"):
            self.b.tasks.execute_command([sys.executable,"-c","print('different')"],"turbo-command-1")
        with self.assertRaisesRegex(BridgeError,"TASK_BUSY"):
            self.b.write_file("blocked.txt","busy")
        self.b.tasks.stop_task_run(first["run_id"],"turbo-command-stop")
        self.assertTrue(self.b.tasks.runs[first["run_id"]]["done"].wait(3))

    def test_workspace_switch_scopes_journals_and_inflight_calls(self):
        self.b.close()
        config=self.home/"selection-config.json"
        config.write_text(json.dumps({"workspace_root":str(self.root),"state_dir":str(self.home/"selected-state"),
                                      "tasks":{"sample_test":[sys.executable,"sample.py"]}}))
        second=self.home/"second project";second.mkdir()
        session=WorkspaceSession(config,lambda c:LocalBridge(c,FakeRuntime(c.workspace_root)))
        try:
            initial=session.info()["context_id"]
            change=session.current.prepare_changes("first root",[{"path":"unique.txt","content":"root one"}],"scope-prepare-1")
            with session.use(initial,True):
                with self.assertRaisesRegex(BridgeError,"TASK_BUSY"):
                    session.switch(initial,workspace_root=str(second))
            switched=session.switch(initial,workspace_root=str(second))
            with self.assertRaisesRegex(BridgeError,"CONTEXT_CHANGED"):
                with session.use(initial,True):pass
            with self.assertRaisesRegex(BridgeError,"NOT_FOUND"):
                session.current.apply_changes(change["change_id"],"wrong-root-apply")
            self.assertNotIn("sample_test",switched["approved_tasks"])
            self.assertFalse((second/"unique.txt").exists())
            restored=session.switch(switched["context_id"],workspace_root=str(self.root))
            session.current.apply_changes(change["change_id"],"right-root-apply")
            self.assertEqual((self.root/"unique.txt").read_text(),"root one")
            run=session.current.tasks.start_task("sample_test","switch-busy-task")
            with self.assertRaisesRegex(BridgeError,"TASK_BUSY"):
                session.switch(restored["context_id"],mode="turbo")
            session.current.tasks.stop_task_run(run["run_id"],"switch-busy-stop")
            self.assertTrue(session.current.tasks.runs[run["run_id"]]["done"].wait(3))
            for target in (self.home, Path(__file__).resolve().parent.parent, session.selection.parent):
                with self.assertRaisesRegex(BridgeError,"WORKSPACE_DENIED"):
                    session.switch(restored["context_id"],workspace_root=str(target))
        finally:
            session.close()
            self.b=LocalBridge(self.config,FakeRuntime(self.root))

    def test_turbo_mcp_call_is_exact_and_not_replayed(self):
        with self.assertRaisesRegex(BridgeError,"MODE_REQUIRED"):
            self.b.call_mcp_tool("id",{},"mcp-call-1")
        self.b.config=replace(self.config,mode="turbo")
        self.b.docs_thread="technical-context"
        self.b.mcp_tools={"known":{"server":"installed","name":"selected"}}
        calls=[]
        def rpc(method,params,timeout=30):
            calls.append((method,params))
            return {"content":[{"type":"text","text":"done"}]}
        self.runtime.call=rpc
        first=self.b.call_mcp_tool("known",{"x":1},"mcp-call-1")
        self.assertEqual(first,self.b.call_mcp_tool("known",{"x":1},"mcp-call-1"))
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][1]["server"],"installed")
        with self.assertRaisesRegex(BridgeError,"IDEMPOTENCY_CONFLICT"):
            self.b.call_mcp_tool("known",{"x":2},"mcp-call-1")
        with self.assertRaisesRegex(BridgeError,"SCOPE_DENIED"):
            self.b.call_mcp_tool("not-discovered",{},"mcp-call-2")
        def lost(*args,**kwargs):raise BridgeError("RUNTIME_TIMEOUT")
        self.runtime.call=lost
        with self.assertRaisesRegex(BridgeError,"RUNTIME_TIMEOUT"):
            self.b.call_mcp_tool("known",{},"mcp-call-lost")
        with self.assertRaisesRegex(BridgeError,"RESULT_UNKNOWN"):
            self.b.call_mcp_tool("known",{},"mcp-call-lost")

    def test_turbo_profile_keeps_write_boundary(self):
        runtime=AppServer(self.root,self.home/"state",mode="turbo")
        self.assertTrue(runtime.cache.is_relative_to(self.root))
        overrides=process_overrides(self.root,runtime.cache,[],"turbo",runtime.state)
        self.assertIn("features.plugins=true",overrides)
        self.assertIn("features.apps=true",overrides)
        self.assertIn("windows.sandbox=\"elevated\"",overrides)
        self.assertFalse(any(x.startswith("mcp_servers=") for x in overrides))
        filesystem=next(v for v in overrides if v.startswith("permissions.bridge.filesystem="))
        self.assertIn(json.dumps(str(runtime.state))+"=\"deny\"",filesystem)
        self.assertIn('\":root\"=\"read\"',filesystem)
        self.b.config=replace(self.config,mode="turbo")
        with self.assertRaises(BridgeError):self.b.write_file("../outside.txt","denied")
        outside=self.home/"outside.txt";outside.write_text("outside read")
        self.assertEqual(self.b.read_file(str(outside))["content"],"outside read")
        with self.assertRaises(BridgeError):self.b.write_file(str(outside),"denied")
        with self.assertRaises(BridgeError):self.b.read_file(str(self.b.state/"journal.sqlite3"))
        self.b.write_file(".env.local","USER_SUPPLIED_EXAMPLE=yes")
        self.assertTrue((self.root/".env.local").is_file())


def run_tests():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BridgeTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__=="__main__":
    run_tests()

"""Run: uv run --with mcp==2.2.0 --python 3.13 server.py --self-test."""
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
from unittest.mock import patch

from bridge import LocalBridge
from files import BridgeConfig, BridgeError, ChangeJournal, _sha256, load_config
from runtime import ALLOWED_METHODS, AppServer, clean_environment, process_overrides


class FakeRuntime:
    """Deterministic protocol peer. These checks do not certify an OS sandbox."""
    def __init__(self, root):
        self.root=root
        self.listeners=[]
        self.command_ready=True
        self.command_error=""
        self.execution_mode="normal"
        self.status="connected"
        self.version="test-peer"
        self.error=None
        self.calls=[]
        self.release=threading.Event()

    @property
    def can_execute(self):
        return self.command_ready if self.execution_mode == "normal" else self.status == "connected"

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

    def test_prepare_changes_preserves_existing_line_endings(self):
        lf=b"one\nneedle\nthree\n"
        crlf=b"one\r\nneedle\r\nthree\r\n"
        (self.root/"lf.txt").write_bytes(lf)
        (self.root/"crlf.txt").write_bytes(crlf)
        change=self.change([
            {"path":"lf.txt","content":"one\r\nchanged\r\nthree\r\n","expected_sha256":_sha256(lf)},
            {"path":"crlf.txt","content":"one\nchanged\nthree\n","expected_sha256":_sha256(crlf)},
        ],"line-endings-001")
        self.b.apply_changes(change,"line-endings-apply-001")
        self.assertEqual((self.root/"lf.txt").read_bytes(),b"one\nchanged\nthree\n")
        self.assertEqual((self.root/"crlf.txt").read_bytes(),b"one\r\nchanged\r\nthree\r\n")
        (self.root/"patch.txt").write_bytes(lf)
        self.b.apply_patch("patch.txt","needle\r\n","patched\r\n",_sha256(lf))
        self.assertEqual((self.root/"patch.txt").read_bytes(),b"one\npatched\nthree\n")
        (self.root/"write.txt").write_bytes(crlf)
        written=self.b.write_file("write.txt","one\ntwo\n",_sha256(crlf))
        self.assertEqual((self.root/"write.txt").read_bytes(),b"one\r\ntwo\r\n")
        self.assertEqual(written["sha256"],_sha256(b"one\r\ntwo\r\n"))
        self.assertEqual(written["bytes_written"],len(b"one\r\ntwo\r\n"))

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
        def rejected(*args,**kwargs):raise BridgeError("RUNTIME_TIMEOUT: result unknown")
        runtime.call=rejected
        with self.assertRaisesRegex(BridgeError,"RUNTIME_TIMEOUT"):
            runtime.command([sys.executable],"unknown-run",1)
        self.assertFalse(runtime.command_ready)
        self.assertEqual(runtime.status,"stopped")

    def test_runtime_modes_and_turbo_bash(self):
        self.assertEqual(self.b.project_info()["runtime"]["mode"], "normal")
        with self.assertRaisesRegex(BridgeError, "TURBO_CONFIRMATION_REQUIRED"):
            self.b.set_runtime_mode("turbo")
        self.runtime.command_ready=False
        self.b.set_runtime_mode("turbo", True)
        info=self.b.project_info()
        self.assertTrue(info["runtime"]["commands_enabled"])
        self.assertTrue(info["runtime"]["bash_enabled"])
        with patch("bridge._git_bash_executable", return_value=Path(sys.executable)):
            result=self.b.run_bash("printf turbo")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(self.runtime.calls[-1][1][1:], ["-c", "printf turbo"])
        self.b.set_runtime_mode("normal")
        with self.assertRaisesRegex(BridgeError, "TURBO_REQUIRED"):
            self.b.run_bash("printf blocked")

    def test_project_info_hides_stale_command_error_when_capability_recovers(self):
        self.runtime.command_ready=False
        self.runtime.command_error="Windows refused the protected process."
        failed=self.b.project_info()
        self.assertFalse(failed["runtime"]["commands_enabled"])
        self.assertEqual(failed["runtime"]["command_error"],self.runtime.command_error)
        self.b.set_runtime_mode("turbo",True)
        recovered=self.b.project_info()
        self.assertTrue(recovered["runtime"]["commands_enabled"])
        self.assertTrue(recovered["runtime"]["bash_enabled"])
        self.assertIsNone(recovered["runtime"]["command_error"])
        self.assertIsNone(self.b.tasks.list_tasks()["unavailable_reason"])

    def test_app_server_uses_separate_normal_and_turbo_command_policy(self):
        runtime=AppServer(self.root,self.home/"state-policy")
        runtime.status="connected"
        runtime.command_ready=True
        calls=[]
        def accepted(method, params, timeout=30):
            calls.append(params)
            return {"exitCode":0,"stdout":"","stderr":""}
        runtime.call=accepted
        runtime.command([sys.executable],"normal-run",1,stream=False)
        self.assertEqual(calls[-1]["permissionProfile"], "bridge")
        self.assertNotIn("sandboxPolicy", calls[-1])
        runtime.execution_mode="turbo"
        runtime.command_ready=False
        runtime.command([sys.executable],"turbo-run",1,stream=False)
        self.assertEqual(calls[-1]["sandboxPolicy"], {"type":"dangerFullAccess"})
        self.assertNotIn("permissionProfile", calls[-1])

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

    def test_git_diff_check_accepts_crlf_but_rejects_real_trailing_whitespace(self):
        def git(*args):
            return subprocess.run([shutil.which("git"),*args],cwd=self.root,capture_output=True,check=True)
        checker=Path(__file__).with_name("git_diff_check.py")
        def check():
            return subprocess.run([sys.executable,str(checker)],cwd=self.root,capture_output=True)
        git("init")
        path=self.root/"line-endings.txt"
        path.write_bytes(b"one\r\n")
        git("add","line-endings.txt")
        path.write_bytes(b"two\r\n")
        self.assertEqual(check().returncode,0)
        path.write_bytes(b"two   \r\n")
        result=check()
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b"trailing whitespace",result.stdout+result.stderr)
        path.write_bytes(b"two\n")
        self.assertEqual(check().returncode,0)

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
        filesystem=next(v for v in overrides if v.startswith("permissions.bridge.filesystem="))
        self.assertNotIn(json.dumps(str(self.root/".git"))+"=",filesystem)
        external=self.home/"external-read";external.mkdir()
        overrides=process_overrides(self.root,self.home/"cache",[],[external])
        filesystem=next(v for v in overrides if v.startswith("permissions.bridge.filesystem="))
        self.assertIn(json.dumps(str(external))+"=\"read\"",filesystem)
        self.assertIn("permissions.bridge.network.enabled=true"," ".join(overrides))
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
        parent_config=self.home/"parent-config.json"
        parent_config.write_text(json.dumps({"workspace_root":str(self.root),"external_read_roots":[str(self.home)]}))
        with self.assertRaisesRegex(BridgeError,"external_read_roots"):
            load_config(parent_config)
        selected=self.home/"selected-project";selected.mkdir();(selected/"runtime").mkdir()
        (self.home/"project-path.txt").write_text(str(selected),encoding="utf-8")
        selected_config=self.home/"selector-config.json"
        selected_config.write_text(json.dumps({"workspace_root":"${PROJECT_ROOT}",
            "tasks":{"sample":["python","${PROJECT_ROOT}/sample.py"]},
            "runtime_read_roots":["${PROJECT_ROOT}/runtime"]}),encoding="utf-8")
        prior_project=os.environ.pop("CODEX_BRIDGE_PROJECT_ROOT",None)
        try:
            configured=load_config(selected_config)
            self.assertEqual(configured.workspace_root,selected.resolve())
            self.assertEqual(configured.tasks["sample"][1].replace("\\","/"),
                             str(selected.resolve()/"sample.py").replace("\\","/"))
            optional_config=self.home/"optional-runtime.json"
            optional_config.write_text(json.dumps({"workspace_root":"${PROJECT_ROOT}",
                "runtime_read_roots":["${PROJECT_ROOT}/missing-runtime"]}),encoding="utf-8")
            self.assertEqual(load_config(optional_config).runtime_read_roots,())
            profiles=self.home/"project-profiles";profiles.mkdir()
            (profiles/"selected.json").write_text(json.dumps({"workspace_root":str(selected),
                "runtime_read_roots":["${PROJECT_ROOT}/runtime"],
                "tasks":{"profile_test":["python","-m","pytest"]}}),encoding="utf-8")
            profiled=load_config(selected_config)
            self.assertIn("profile_test",profiled.tasks)
            self.assertIn(selected/"runtime",profiled.runtime_read_roots)
            override=self.home/"override-project";override.mkdir();(override/"runtime").mkdir()
            os.environ["CODEX_BRIDGE_PROJECT_ROOT"]=str(override)
            self.assertEqual(load_config(selected_config).workspace_root,override.resolve())
        finally:
            if prior_project is None:os.environ.pop("CODEX_BRIDGE_PROJECT_ROOT",None)
            else:os.environ["CODEX_BRIDGE_PROJECT_ROOT"]=prior_project

    def test_task_runtime_must_be_explicitly_allowlisted(self):
        runtime_dir=self.root/".venv-paxg";runtime_dir.mkdir()
        executable=runtime_dir/"Scripts"/"python.exe";executable.parent.mkdir();executable.write_bytes(b"test")
        self.b.config=replace(self.b.config,tasks={"local":(str(executable),)},runtime_read_roots=())
        with self.assertRaisesRegex(BridgeError,"outside the project or in runtime_read_roots"):
            self.b.tasks._command("local")
        self.b.config=replace(self.b.config,runtime_read_roots=(runtime_dir,))
        self.assertEqual(Path(self.b.tasks._command("local")[0]).resolve(),executable.resolve())
        with self.assertRaisesRegex(BridgeError,"runtime roots are execution-only"):
            self.b.read_file(".venv-paxg/Scripts/python.exe")

    def test_mcp_schema_and_ui_contract(self):
        import server
        tools=asyncio.run(server.mcp.list_tools())
        self.assertEqual(len(tools),37)
        self.assertEqual(server.mcp._lowlevel_server.extensions,{
            "io.modelcontextprotocol/ui": {},
            "io.modelcontextprotocol/tasks": {},
        })
        linked=[t.name for t in tools if (t.meta or {}).get("ui",{}).get("resourceUri")]
        self.assertEqual(linked,["show_control_panel","set_runtime_mode","show_security_scan_panel"])
        self.runtime.command_ready=False
        panel=self.b.show_control_panel()
        self.assertTrue(panel["panel_available"])
        self.assertFalse(panel["task_state"]["available"])
        names={t.name:t for t in tools}
        self.assertEqual(list(names["run_task"].input_schema["properties"]),["task_id","timeout_seconds"])
        self.assertTrue(all(t.annotations and t.output_schema for t in tools))
        contents=list(asyncio.run(server.mcp.read_resource(server.UI_URI)))
        self.assertEqual(contents[0].mime_type,"text/html;profile=mcp-app")
        html=contents[0].content
        for required in ("ui/initialize","ui/notifications/initialized","ui/notifications/tool-input","tools/call","ui/notifications/tool-result","2000","Normal (An toàn)","Turbo (Mở quyền)","Áp dụng đợt sửa","Hoàn tác đợt sửa","MCP Diagnostics","Copy diagnostics"):
            self.assertIn(required,html)
        for unsafe in ("eval(","http://localhost","<script src=","/assets/"):
            self.assertNotIn(unsafe,html)


def run_tests():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BridgeTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__=="__main__":
    run_tests()

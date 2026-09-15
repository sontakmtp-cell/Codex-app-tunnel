"""Owned Windows jobs and protected task streaming for Codex's buffered Windows API."""
import base64
import csv
import ctypes
import hmac
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import uuid
from ctypes import wintypes as w


def preserve_owner_access(*folders):
    # OWNER RIGHTS alone follows the sandbox creator of new files, locking out
    # the desktop user. Give that same user an explicit inheritable Modify ACE.
    system = Path(os.environ["SYSTEMROOT"]) / "System32"
    identity = subprocess.check_output([str(system/"whoami.exe"), "/user", "/fo", "csv", "/nh"],
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=10).decode().strip()
    sid = next(csv.reader([identity]))[1]
    for folder in folders:
        subprocess.run([str(system/"icacls.exe"), str(folder), "/grant", "*"+sid+":(OI)(CI)M"],
            check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)


class BasicLimits(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", w.DWORD), ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t),
                ("active", w.DWORD), ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                ("process_mem", ctypes.c_size_t), ("job_mem", ctypes.c_size_t),
                ("peak_process_mem", ctypes.c_size_t), ("peak_job_mem", ctypes.c_size_t)]


class OwnedJob:
    def __init__(self):
        self.lock = threading.Lock()
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = ExtendedLimits()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign_and_resume(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [w.HANDLE]
        ntdll.NtResumeProcess.restype = w.LONG
        if ntdll.NtResumeProcess(int(process._handle)) != 0:
            raise OSError("Cannot resume the owned App Server process.")

    def close(self):
        with self.lock:
            handle, self.handle = self.handle, None
        if handle:
            self.kernel.CloseHandle(handle)


def stream_command(runtime, argv, process_id, timeout):
    # Codex 0.154 Windows rejects streaming/terminate. The helper stays inside its
    # permission profile; this temporary loopback channel carries logs and Stop only.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(.2)
    token = uuid.uuid4().hex
    finished = threading.Event()
    relay = {"socket": None, "stop": False}
    with runtime.lock:
        runtime.windows_commands[process_id] = relay

    def receive():
        try:
            while not finished.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(2)
                    with connection.makefile("rb") as reader:
                        if not hmac.compare_digest(reader.readline(128), (token+"\n").encode()):
                            continue
                        connection.settimeout(None)
                        with runtime.lock:
                            relay["socket"] = connection
                            if relay["stop"]:
                                connection.sendall(b"stop\n")
                        while line := reader.readline(8192):
                            message = json.loads(line)
                            for callback in tuple(runtime.listeners):
                                callback("command/exec/outputDelta", {**message, "processId": process_id})
                        return
        except (OSError, ValueError):
            if not finished.is_set():
                runtime.close()  # Never leave a task running without its control channel.

    receiver = threading.Thread(target=receive, daemon=True)
    receiver.start()
    try:
        # Reuse this exact helper/OwnedJob code without granting reads of bridge state.
        command = [sys.executable, "-I", "-c", Path(__file__).read_text(encoding="utf-8"),
                   str(listener.getsockname()[1]), token, *argv]
        result = runtime.command(command, process_id, timeout, stream=False)
        receiver.join(2)
        for stream in ("stdout", "stderr"):
            if result.get(stream):
                for callback in tuple(runtime.listeners):
                    callback("command/exec/outputDelta", {"processId": process_id, "stream": stream,
                        "deltaBase64": base64.b64encode(result[stream].encode()).decode()})
        return result
    finally:
        finished.set()
        with runtime.lock:
            runtime.windows_commands.pop(process_id, None)
            connection = relay["socket"]
        if connection:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        listener.close()
        receiver.join(2)


def task_main():
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 10) as connection:
        connection.sendall((sys.argv[2]+"\n").encode())
        connection.settimeout(None)
        send_lock = threading.Lock()
        job = OwnedJob()
        process = None
        try:
            process = subprocess.Popen(sys.argv[3:], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
            job.assign_and_resume(process)

            def stop():
                try:
                    connection.recv(16)
                except OSError:
                    pass
                finally:
                    job.close()  # Stop or a disconnected bridge closes this task's entire tree.

            def forward(pipe, stream):
                with pipe:
                    while data := pipe.read1(4096):
                        line = json.dumps({"stream": stream, "deltaBase64": base64.b64encode(data).decode()})+"\n"
                        try:
                            with send_lock:
                                connection.sendall(line.encode())
                        except OSError:
                            job.close()
                            return

            threading.Thread(target=stop, daemon=True).start()
            readers = [threading.Thread(target=forward, args=(pipe, stream), daemon=True)
                       for pipe, stream in ((process.stdout, "stdout"), (process.stderr, "stderr"))]
            for reader in readers:
                reader.start()
            code = process.wait()
            job.close()
            for reader in readers:
                reader.join(2)
            return code
        finally:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            job.close()
            if process and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(task_main())

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import queue
import tempfile
import unittest
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_mcp import (  # noqa: E402
    NATIVE_TOOL_ALLOWLIST,
    REQUIRED_NATIVE_TOOLS,
    SecurityMcpAdapter,
    SecurityMcpConfigurationError,
    SecurityMcpError,
    SecurityMcpIdempotencyConflict,
    SecurityMcpTimeout,
    build_security_environment,
    find_bundled_node,
    find_security_plugin,
)


class _FakeStdout:
    def __init__(self):
        self._queue = queue.Queue()

    def push(self, value):
        self._queue.put(value)

    def stop(self):
        self._queue.put(None)

    def __iter__(self):
        return self

    def __next__(self):
        value = self._queue.get()
        if value is None:
            raise StopIteration
        return value


class _FakeStdin:
    def __init__(self, process):
        self.process = process

    def write(self, data):
        self.process.handle(json.loads(data.decode("utf-8")))
        return len(data)

    def flush(self):
        return None


class _FakeStderr:
    @staticmethod
    def read(_size):
        return b""


class _FakeProcess:
    def __init__(self, factory, argv, kwargs):
        self.factory = factory
        self.argv = argv
        self.kwargs = kwargs
        self.stdout = _FakeStdout()
        self.stderr = _FakeStderr()
        self.stdin = _FakeStdin(self)
        self.returncode = None
        self._handle = 1
        self.tool_calls = []
        self.tool_arguments = []
        self.handoff_token = None

    def poll(self):
        return self.returncode

    def handle(self, message):
        if "id" not in message:
            return
        method = message.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name": "fake"}}
        elif method == "tools/list":
            names = sorted(REQUIRED_NATIVE_TOOLS | {"start_codex_security_deep_scan"})
            result = {"tools": [{"name": name} for name in names]}
        elif method == "tools/call":
            name = message.get("params", {}).get("name")
            self.tool_calls.append(name)
            self.tool_arguments.append((name, message.get("params", {}).get("arguments", {})))
            if self.factory.suppress_tool_responses:
                return
            if name == "open_codex_security_workspace":
                result = {"structuredContent": {"workspace": {"id": "workspace-1"}}}
            elif name == "submit_codex_security_setup":
                result = {"structuredContent": {"setup": {"submitted": True}}}
            elif name == "start_codex_security_scan":
                result = {
                    "structuredContent": {"workspace": {"results": {"scanId": "scan-1"}}},
                    "status": "running",
                }
            elif name == "get_codex_security_scan":
                result = {"structuredContent": {"scan": {
                    "scanId": "scan-1",
                    "handoffStatus": "delivered" if self.handoff_token else "pending",
                    "handoffClaimToken": self.handoff_token,
                    "progress": {"status": "running"},
                }}}
            elif name == "claim_codex_security_scan_handoff_delivery":
                self.handoff_token = message.get("params", {}).get("arguments", {}).get("claimToken")
                result = {"structuredContent": {"scan": {
                    "scanId": "scan-1", "handoffStatus": "pending", "handoffClaimToken": self.handoff_token,
                }}}
            elif name == "mark_codex_security_scan_handoff_delivered":
                result = {"structuredContent": {"scan": {
                    "scanId": "scan-1", "handoffStatus": "delivered", "handoffClaimToken": self.handoff_token,
                }}}
            else:
                result = {}
        else:
            result = {}
        self.stdout.push((json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\n").encode())

    def terminate(self):
        self.returncode = 1
        self.stdout.stop()

    def kill(self):
        self.returncode = -9
        self.stdout.stop()

    def wait(self, timeout=None):
        return self.returncode


@dataclass
class _FakePopen:
    suppress_tool_responses: bool = False

    def __post_init__(self):
        self.instances = []

    def __call__(self, argv, **kwargs):
        process = _FakeProcess(self, argv, kwargs)
        self.instances.append(process)
        return process


class SecurityMcpAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="security-mcp-test-")
        base = Path(self.temp.name)
        self.target = base / "target"
        self.target.mkdir()
        self.state = base / "state"
        self.plugin = base / "codex-security"
        (self.plugin / "mcp").mkdir(parents=True)
        (self.plugin / ".codex-plugin").mkdir()
        (self.plugin / ".codex-plugin" / "plugin.json").write_text(
            json.dumps({"name": "codex-security", "version": "test"}), encoding="utf-8"
        )
        (self.plugin / "mcp" / "server.mjs").write_text("// fake server", encoding="utf-8")
        self.node = base / "node.exe"
        self.node.write_bytes(b"fake")

    def tearDown(self):
        self.temp.cleanup()

    def adapter(self, **kwargs):
        return SecurityMcpAdapter(
            self.state,
            self.target,
            plugin_root=self.plugin,
            node_path=self.node,
            call_timeout=kwargs.pop("call_timeout", 0.2),
            **kwargs,
        )

    def start_adapter(self, popen):
        adapter = self.adapter()
        with patch("security_mcp.subprocess.Popen", popen), patch("security_mcp._make_job", return_value=None):
            adapter.start()
        return adapter

    def test_path_resolution_fails_closed(self):
        with self.assertRaises(SecurityMcpConfigurationError):
            find_security_plugin(Path(self.temp.name) / "missing")
        with self.assertRaises(SecurityMcpConfigurationError):
            find_bundled_node(Path(self.temp.name) / "missing-node.exe")

    def test_environment_excludes_inherited_secrets_and_codex_home(self):
        with patch.dict(
            "os.environ",
            {"OPENAI_API_KEY": "secret", "CODEX_HOME": "C:/secret-home", "NODE_OPTIONS": "--inspect"},
            clear=False,
        ):
            env = build_security_environment(self.state / "security", self.target)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("CODEX_HOME", env)
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertEqual(env["CODEX_SECURITY_SCAN_ROOT"], str(self.target.resolve()))
        self.assertEqual(env["CODEX_SECURITY_STATE_DIR"], str((self.state / "security").resolve()))

    def test_start_uses_bundled_node_and_filters_native_deep(self):
        popen = _FakePopen()
        adapter = self.start_adapter(popen)
        try:
            self.assertEqual(popen.instances[0].argv, [str(self.node), str(self.plugin / "mcp/server.mjs"), "--stdio"])
            self.assertNotIn("codex.exe", " ".join(popen.instances[0].argv).lower())
            scan_root = Path(popen.instances[0].kwargs["env"]["CODEX_SECURITY_SCAN_ROOT"])
            self.assertEqual(scan_root, (self.state / "security" / "scans").resolve())
            self.assertFalse(scan_root.is_relative_to(self.target.resolve()))
            self.assertEqual({tool["name"] for tool in adapter.list_native_tools()}, NATIVE_TOOL_ALLOWLIST & REQUIRED_NATIVE_TOOLS)
            with self.assertRaisesRegex(SecurityMcpError, "fixed allowlist"):
                adapter.call_tool("start_codex_security_deep_scan", {})
        finally:
            adapter.shutdown()

    def test_native_deep_and_native_model_are_blocked(self):
        popen = _FakePopen()
        adapter = self.start_adapter(popen)
        try:
            with self.assertRaisesRegex(SecurityMcpError, "native Deep"):
                adapter.call_tool("open_codex_security_workspace", {"mode": "deep"}, request_id="deep")
            with self.assertRaisesRegex(SecurityMcpError, "app-only start"):
                adapter.call_tool(
                    "start_codex_security_scan",
                    {"sessionId": "workspace", "model": "gpt-5.6"},
                    request_id="model",
                )
            with self.assertRaisesRegex(SecurityMcpError, "request_id"):
                adapter.call_tool("start_codex_security_scan", {"sessionId": "workspace"})
        finally:
            adapter.shutdown()

    def test_persistent_idempotency_replays_after_restart_and_rejects_payload_conflict(self):
        popen = _FakePopen()
        adapter = self.start_adapter(popen)
        result = adapter.call_mutation("start_codex_security_scan", {"sessionId": "workspace"}, "request-1")
        self.assertEqual(result.scan_id, "scan-1")
        self.assertFalse(result.replayed)
        adapter.shutdown()

        restarted = self.adapter()
        try:
            replay = restarted.call_mutation("start_codex_security_scan", {"sessionId": "workspace"}, "request-1")
            self.assertEqual(replay.scan_id, "scan-1")
            self.assertTrue(replay.replayed)
            self.assertEqual(len(popen.instances), 1)
            with self.assertRaises(SecurityMcpIdempotencyConflict):
                restarted.call_mutation("start_codex_security_scan", {"sessionId": "other"}, "request-1")
        finally:
            restarted.shutdown()

    def test_pending_retry_requires_authoritative_reconciliation(self):
        adapter = self.adapter()
        payload = {"tool": "start_codex_security_scan", "arguments": {"sessionId": "workspace"}}
        adapter.journal.begin("pending-1", payload)
        with self.assertRaisesRegex(SecurityMcpError, "authoritative"):
            adapter.call_mutation("start_codex_security_scan", payload["arguments"], "pending-1", payload=payload)
        replay = adapter.call_mutation(
            "start_codex_security_scan",
            payload["arguments"],
            "pending-1",
            payload=payload,
            reconcile=lambda _record: {"scanId": "scan-authoritative", "status": "running"},
        )
        self.assertEqual(replay.scan_id, "scan-authoritative")
        self.assertTrue(replay.replayed)
        adapter.shutdown()

    def test_start_sequence_has_durable_outer_idempotency(self):
        popen = _FakePopen()
        adapter = self.start_adapter(popen)
        first = adapter.start_scan("standard", {"kind": "codebase"}, None, "start-sequence-1")
        adapter.shutdown()
        restarted = self.adapter()
        try:
            with patch("security_mcp.subprocess.Popen", popen), patch("security_mcp._make_job", return_value=None):
                replay = restarted.start_scan("standard", {"kind": "codebase"}, None, "start-sequence-1")
            self.assertEqual(
                replay["structuredContent"]["workspace"]["results"]["scanId"],
                first["structuredContent"]["workspace"]["results"]["scanId"],
            )
            self.assertEqual(
                popen.instances[0].tool_calls,
                [
                    "open_codex_security_workspace",
                    "submit_codex_security_setup",
                    "start_codex_security_scan",
                    "get_codex_security_scan",
                    "claim_codex_security_scan_handoff_delivery",
                    "mark_codex_security_scan_handoff_delivered",
                ],
            )
            self.assertEqual(popen.instances[1].tool_calls, ["get_codex_security_scan"])
        finally:
            restarted.shutdown()

    def test_chatgpt_deep_progress_stays_on_app_only_native_phases(self):
        popen = _FakePopen()
        adapter = self.start_adapter(popen)
        try:
            started = adapter.start_scan("standard", {"kind": "codebase"}, None, "deep-progress-start")
            scan_id = started["structuredContent"]["workspace"]["results"]["scanId"]
            coverage = {"completeness": "partial", "surfaces": [], "explicitExclusions": [], "deferred": []}
            for index, phase in enumerate(("attack_surface", "auth_data_flow",
                                           "injection_file_process_network_state"), 1):
                adapter.commit_phase(scan_id, phase, {"candidates": [], "coverage": coverage},
                                     f"deep-progress-phase-{index}")
            adapter.commit_phase(scan_id, "deduplicate", {"candidates": [], "coverage": coverage},
                                 "deep-progress-deduplicate")
            progress = [arguments for name, arguments in popen.instances[0].tool_arguments
                        if name == "update_codex_security_scan_progress"]
            self.assertEqual(len(progress), 3)
            self.assertEqual([item["phaseItemsCompleted"] for item in progress], [1, 2, 3])
            self.assertTrue(all(item["phaseItemsTotal"] == 3 for item in progress))
            self.assertTrue(all(item["phaseProgressUnit"] == "review_receipts" for item in progress))
            self.assertTrue(all("deepReviewPass" not in item for item in progress))
        finally:
            adapter.shutdown()

    def test_threat_model_is_normalized_for_native_draft_schema(self):
        popen = _FakePopen()
        adapter = self.start_adapter(popen)
        try:
            started = adapter.start_scan("standard", {"kind": "codebase"}, None, "threat-model-start")
            scan_id = started["structuredContent"]["workspace"]["results"]["scanId"]
            adapter.commit_phase(
                scan_id,
                "threat_model",
                {"threatModel": {
                    "assets": [{"name": "source"}],
                    "trust_boundaries": [{"from": "web", "to": "bridge"}],
                    "threats": [{"id": "T1"}],
                    "scope_limit": "text-only project",
                }},
                "threat-model-commit",
            )
            draft = next(
                arguments for name, arguments in popen.instances[0].tool_arguments
                if name == "record_codex_security_scan_draft"
            )
            model = draft["threatModel"]
            self.assertTrue(model["summary"].startswith("Scope limitation:"))
            self.assertEqual(model["assets"], ['{"name":"source"}'])
            self.assertEqual(model["trustBoundaries"], ['{"from":"web","to":"bridge"}'])
            self.assertEqual(model["threats"], [{"id": "T1"}])
        finally:
            adapter.shutdown()

    def test_timeout_closes_runtime_and_does_not_replay(self):
        popen = _FakePopen(suppress_tool_responses=True)
        adapter = self.adapter(call_timeout=0.02)
        with patch("security_mcp.subprocess.Popen", popen), patch("security_mcp._make_job", return_value=None):
            adapter.start()
            with self.assertRaises(SecurityMcpTimeout):
                adapter.call_mutation("start_codex_security_scan", {"sessionId": "workspace"}, "timeout-1")
        self.assertEqual(popen.instances[0].tool_calls, ["start_codex_security_scan"])
        with self.assertRaisesRegex(SecurityMcpError, "authoritative"):
            adapter.call_mutation("start_codex_security_scan", {"sessionId": "workspace"}, "timeout-1")
        adapter.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)

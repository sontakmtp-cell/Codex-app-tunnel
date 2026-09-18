"""Focused tests for the V1 Security facade contract."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bridge import LocalBridge
from files import BridgeConfig, BridgeError
from security_mcp import SecurityMcpTimeout


class RuntimeStub:
    def __init__(self):
        self.listeners = []
        self.status = "connected"
        self.version = "security-test-peer"
        self.error = None
        self.command_error = ""
        self.execution_mode = "normal"
        self.calls = []

    @property
    def can_execute(self):
        return True

    def close(self):
        self.status = "stopped"


class DirectSecurityAdapter:
    """The intentionally small direct-adapter contract used by the facade."""

    STANDARD_PHASES = (
        "preflight", "inventory", "threat_model", "discovery", "validation",
        "attack_path", "finalization",
    )
    DEEP_PHASES = (
        "preflight", "inventory", "threat_model", "attack_surface", "auth_data_flow",
        "injection_file_process_network_state", "deduplicate", "validation",
        "attack_path", "finalization",
    )

    def __init__(self, root):
        self.root = Path(root)
        self.calls = []
        self.start_calls = []
        self.scans = {}
        self.requests = {}
        self.disable_reconcile = False
        self.next_scan = 0

    def start_scan(self, mode, target, user_context, request_id):
        if request_id in self.requests:
            scan_id = self.requests[request_id]
            return {"workspace": {"results": {"scanId": scan_id}}}
        self.start_calls.append((mode, target, user_context, request_id))
        self.calls.append("start_scan")
        self.next_scan += 1
        scan_id = f"scan-{self.next_scan:04d}"
        self.scans[scan_id] = {
            "status": "running",
            "phase": "preflight",
            "reviewMode": "chatgpt_deep" if user_context == "deep" else "standard",
            "scanDir": str(self.root / "private-scan-state"),
            "handoffToken": "handoff-secret-should-not-escape",
            "workspaceRoot": str(self.root),
        }
        self.requests[request_id] = scan_id
        return {"workspace": {"results": {"scanId": scan_id}}}

    def find_scan_by_request(self, request_id, payload_hash):
        if self.disable_reconcile:
            return None
        scan_id = self.requests.get(request_id)
        return {"workspace": {"results": {"scanId": scan_id}}} if scan_id else None

    def get_scan(self, scan_id):
        self.calls.append("get_scan")
        return {"structuredContent": {"workspace": {"results": dict(self.scans[scan_id])}}}

    def continue_scan(self, scan_id):
        self.calls.append("continue_scan")
        return self.get_scan(scan_id)

    def commit_phase(self, scan_id, phase, phase_data, request_id):
        self.calls.append(("commit_phase", phase, phase_data, request_id))
        state = self.scans[scan_id]
        phases = self.DEEP_PHASES if state.get("reviewMode") == "chatgpt_deep" else self.STANDARD_PHASES
        next_phase = phases[phases.index(phase) + 1] if phases.index(phase) + 1 < len(phases) else "complete"
        state["phase"] = phase if next_phase == "complete" else next_phase
        return self.get_scan(scan_id)

    def complete_scan(self, scan_id, request_id):
        self.calls.append(("complete_scan", request_id))
        self.scans[scan_id]["status"] = "completed"
        self.scans[scan_id]["phase"] = "complete"
        return self.get_scan(scan_id)

    def cancel_scan(self, scan_id, request_id):
        self.calls.append(("cancel_scan", request_id))
        self.scans[scan_id]["status"] = "cancelled"
        return self.get_scan(scan_id)

    def list_findings(self, scan_id, cursor, limit):
        self.calls.append(("list_findings", cursor, limit))
        return {
            "structuredContent": {"findingsPage": {
                "findings": [{
                    "id": "finding-1",
                    "title": "unsafe input",
                    "severity": "high",
                    "description": "token=private-token and /private/path must be hidden",
                    "file": str(self.root / "src" / "app.py"),
                    "locations": [
                        {"path": str(self.root / "src" / "app.py"), "startLine": 91, "endLine": 104,
                         "role": "root_control"},
                        {"path": str(self.root / "src" / "config.py"), "startLine": 22,
                         "role": "expected_control"},
                    ],
                    "token": "private-token",
                }],
                "nextOffset": 1,
                "total": 1,
            }},
        }

    def export_findings(self, scan_id, format):
        self.calls.append(("export_findings", format))
        return json.dumps({
            "findings": [{"file": str(self.root / "src" / "app.py")}],
            "scanDir": str(self.root / "private-scan-state"),
            "token": "private-token",
        })

    def show_security_scan_panel(self):
        self.calls.append("show_security_scan_panel")
        return {
            "repository": {
                "name": self.root.name,
                "workspaceRoot": str(self.root),
                "gitRepository": False,
            },
        }


class ZeroFindingSecurityAdapter(DirectSecurityAdapter):
    def list_findings(self, scan_id, cursor, limit):
        self.calls.append(("list_findings", cursor, limit))
        return {
            "structuredContent": {"findingsPage": {
                "findings": [],
                "nextOffset": None,
                "total": 0,
            }},
        }


class TimeoutCommitSecurityAdapter(DirectSecurityAdapter):
    def __init__(self, root):
        super().__init__(root)
        self.commit_results = {}
        self.timeout_once = True

    def commit_phase(self, scan_id, phase, phase_data, request_id):
        if request_id in self.commit_results:
            return self.commit_results[request_id]
        result = super().commit_phase(scan_id, phase, phase_data, request_id)
        self.commit_results[request_id] = result
        if self.timeout_once:
            self.timeout_once = False
            raise SecurityMcpTimeout("native result is unknown")
        return result


class TimeoutStartSecurityAdapter(DirectSecurityAdapter):
    def __init__(self, root):
        super().__init__(root)
        self.timeout_once = True

    def start_scan(self, mode, target, user_context, request_id):
        result = super().start_scan(mode, target, user_context, request_id)
        if self.timeout_once:
            self.timeout_once = False
            raise SecurityMcpTimeout("native start result is unknown")
        return result


class TimeoutFindingsSecurityAdapter(DirectSecurityAdapter):
    def list_findings(self, scan_id, cursor, limit):
        self.calls.append(("list_findings", cursor, limit))
        raise SecurityMcpTimeout("native findings result is unavailable")


class SecurityBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="security-bridge-test-")
        base = Path(self.temp.name)
        self.root = base / "project"
        self.root.mkdir()
        self.config = BridgeConfig(self.root, {}, state_dir=base / "state")
        self.runtime = RuntimeStub()
        self.adapter = DirectSecurityAdapter(self.root)
        self.bridge = LocalBridge(self.config, self.runtime, security_adapter=self.adapter)

    def tearDown(self):
        self.bridge.close()
        self.temp.cleanup()

    def new_bridge(self, state_name, adapter=None):
        base = Path(self.temp.name)
        runtime = RuntimeStub()
        config = BridgeConfig(self.root, {}, state_dir=base / state_name)
        return LocalBridge(config, runtime, security_adapter=adapter or DirectSecurityAdapter(self.root))

    def test_standard_workflow_mapping_guard_and_terminal_mutation_guard(self):
        with self.assertRaisesRegex(BridgeError, "review_mode"):
            self.bridge.security_start_scan("native_deep", "codebase", request_id="invalid-001")
        started = self.bridge.security_start_scan("standard", "codebase", request_id="start-001")
        self.assertEqual(started["scanId"], "scan-0001")
        self.assertEqual(started["nextPhase"], "inventory")
        self.assertEqual(self.adapter.start_calls[0][:2], ("standard", {"kind": "codebase"}))
        self.assertEqual(self.runtime.calls, [])
        resumed = self.bridge.security_continue_scan("scan-0001")
        self.assertEqual(resumed["nextPhase"], "inventory")

        with self.assertRaisesRegex(BridgeError, "SECURITY_PHASE_ORDER"):
            self.bridge.security_commit_phase("scan-0001", "discovery", request_id="wrong-001",
                                              candidates=[], coverage={})

        phase_data = {
            "preflight": {"coverage": {"files": 1}},
            "inventory": {"coverage": {"files": 1}, "boundaries": ["bridge"]},
            "threat_model": {"threatModel": {"threats": []}},
            "discovery": {"candidates": [], "coverage": {"files": 1}},
            "validation": {"validations": [], "coverage": {"validated": 0}},
            "attack_path": {"attackPaths": [], "coverage": {"paths": 0}},
        }
        phase = "preflight"
        for phase, fields in phase_data.items():
            view = self.bridge.security_commit_phase("scan-0001", phase, request_id="phase-reused", **fields)
            self.assertEqual(view["scanId"], "scan-0001")
        self.assertEqual(view["phase"], "finalization")

        with self.assertRaisesRegex(BridgeError, "findings must be a list"):
            self.bridge.security_commit_phase(
                "scan-0001",
                "finalization",
                request_id="empty-finalization",
                coverage={"completeness": "partial", "deferred": [{"id": "F1"}]},
            )
        with self.assertRaisesRegex(BridgeError, "SECURITY_FINALIZATION_REQUIRED"):
            self.bridge.security_complete_scan("scan-0001", "complete-before-finalization")

        self.bridge.security_commit_phase(
            "scan-0001",
            "finalization",
            request_id="phase-reused",
            findings=[],
            coverage={"complete": True},
        )
        completed = self.bridge.security_complete_scan("scan-0001", "complete-001")
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["phase"], "complete")

        with self.assertRaisesRegex(BridgeError, "SECURITY_TERMINAL"):
            self.bridge.security_commit_phase("scan-0001", "finalization", request_id="late-001",
                                              findings=[], coverage={})

    def test_mcp_scan_resource_reads_authoritative_state(self):
        import server

        previous = server._bridge
        server._bridge = self.bridge
        try:
            started = self.bridge.security_start_scan("standard", "codebase", request_id="resource-scan-001")
            payload = json.loads(server.bridge_security_scan_state_resource(started["scanId"]))
            self.assertEqual(payload["scanId"], started["scanId"])
            self.assertEqual(payload["status"], "running")
            self.assertIn("revision", payload)
        finally:
            server._bridge = previous

    def test_chatgpt_deep_scan_can_complete_with_zero_findings(self):
        adapter = ZeroFindingSecurityAdapter(self.root)
        bridge = self.new_bridge("zero-findings-state", adapter)
        try:
            started = bridge.security_start_scan(
                "chatgpt_deep", "codebase", user_context="deep", request_id="zero-start-001"
            )
            phase_data = {
                "preflight": {"coverage": {"files": 1}},
                "inventory": {"inventory": [{"path": "src/app.py"}], "coverage": {"files": 1}},
                "threat_model": {"threatModel": {"threats": []}},
                "attack_surface": {"candidates": [], "coverage": {"surfaces": []}},
                "auth_data_flow": {"candidates": [], "coverage": {"surfaces": []}},
                "injection_file_process_network_state": {"candidates": [], "coverage": {"surfaces": []}},
                "deduplicate": {"candidates": [], "coverage": {"deduplicated": 0}},
                "validation": {"validations": [], "coverage": {"validated": 0}},
                "attack_path": {"attackPaths": [], "coverage": {"paths": 0}},
            }
            for index, (phase, fields) in enumerate(phase_data.items(), start=1):
                bridge.security_commit_phase(
                    started["scanId"], phase, request_id=f"zero-phase-{index}", **fields
                )

            finalized = bridge.security_commit_phase(
                started["scanId"], "finalization", request_id="zero-finalization-001", findings=[]
            )
            self.assertEqual(finalized["phase"], "finalization")
            self.assertEqual(finalized["nextPhase"], "complete")

            state = bridge.security_get_scan(started["scanId"])
            self.assertEqual(state["nextPhase"], "complete")
            completed = bridge.security_complete_scan(started["scanId"], "zero-complete-001")
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["phase"], "complete")

            findings = bridge.security_list_findings(started["scanId"])
            self.assertEqual(findings["total"], 0)
            self.assertEqual(findings["findings"], [])
        finally:
            bridge.close()

    def test_completed_scan_reads_cached_findings_and_aggregates(self):
        adapter = TimeoutFindingsSecurityAdapter(self.root)
        bridge = self.new_bridge("completed-cache-state", adapter)
        try:
            all_findings = [
                {"id": f"F{index}", "title": "finding", "severity": "low",
                 "file": "src/app.py", "line": index + 1}
                for index in range(205)
            ]
            started = bridge.security_start_scan("standard", "codebase", request_id="cache-start-001")
            phase_data = {
                "preflight": {"coverage": {"files": 2}},
                "inventory": {"inventory": [{"path": "src/app.py"}], "coverage": {"files": 2}},
                "threat_model": {"threatModel": {"threats": []}},
                "discovery": {"candidates": [], "coverage": {"files": 2}},
                "validation": {"validations": [], "coverage": {"validated": 2}},
                "attack_path": {"attackPaths": [], "coverage": {"paths": 0}},
                "finalization": {
                    "findings": all_findings,
                    "coverage": {"complete": True, "files": 2},
                },
            }
            for index, (phase, fields) in enumerate(phase_data.items(), start=1):
                bridge.security_commit_phase(
                    started["scanId"], phase, request_id=f"cache-phase-{index}", **fields
                )

            completed = bridge.security_complete_scan(started["scanId"], "cache-complete-001")
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["findingCounts"]["total"], 205)
            self.assertEqual(completed["coverageSoFar"]["files"], 2)

            first_page = bridge.security_list_findings(started["scanId"], limit=100)
            self.assertEqual(first_page["total"], 205)
            self.assertEqual(first_page["findings"][0]["id"], "F0")
            self.assertEqual(first_page["nextCursor"], 100)
            second_page = bridge.security_list_findings(started["scanId"], cursor=100, limit=100)
            self.assertEqual(second_page["findings"][0]["id"], "F100")
            self.assertEqual(second_page["nextCursor"], 200)
            third_page = bridge.security_list_findings(started["scanId"], cursor=200, limit=100)
            self.assertEqual(len(third_page["findings"]), 5)
            self.assertEqual(third_page["findings"][-1]["id"], "F204")
            self.assertIsNone(third_page["nextCursor"])
            self.assertEqual([call for call in adapter.calls if isinstance(call, tuple) and call[0] == "list_findings"], [])
        finally:
            bridge.close()

    def test_restart_retry_is_atomic_and_payload_conflict_is_rejected(self):
        first = self.bridge.security_start_scan("standard", "codebase", "same context", "restart-001")
        # Simulate a crash after the direct adapter created the scan but before
        # the facade persisted scan_id in its own journal.
        self.bridge.db.execute(
            "UPDATE security_requests SET scan_id=NULL,status='pending' WHERE request_id=?",
            ("restart-001",),
        )
        self.bridge.db.commit()
        self.adapter.disable_reconcile = True
        self.bridge.close()
        self.bridge = self.new_bridge("state", self.adapter)
        retry = self.bridge.security_start_scan("standard", "codebase", "same context", "restart-001")
        self.assertEqual(retry["scanId"], first["scanId"])
        self.assertEqual(len(self.adapter.start_calls), 1)
        with self.assertRaisesRegex(BridgeError, "IDEMPOTENCY_CONFLICT"):
            self.bridge.security_start_scan("standard", "codebase", "different context", "restart-001")

    def test_deep_and_changes_mapping_use_no_runtime_worker(self):
        deep = self.bridge.security_start_scan("chatgpt_deep", "codebase", user_context="deep", request_id="deep-001")
        self.assertEqual(deep["reviewMode"], "chatgpt_deep")
        self.assertEqual(self.adapter.start_calls[-1][0], "standard")
        self.bridge.security_cancel_scan(deep["scanId"], "deep-cancel-001")

        changes_bridge = self.new_bridge("changes-state")
        try:
            with patch("bridge.git_repository", return_value=True):
                result = changes_bridge.security_start_scan("standard", "changes", request_id="changes-001")
            self.assertEqual(changes_bridge.security_adapter.start_calls[0][:2],
                             ("diff", {"kind": "working_tree"}))
            changes_bridge.security_cancel_scan(result["scanId"], "changes-cancel-001")
        finally:
            changes_bridge.close()
        self.assertEqual(self.runtime.calls, [])

    def test_widget_request_id_resolves_authoritative_scan(self):
        started = self.bridge.security_start_scan("standard", "codebase", request_id="widget-start-001")
        resolved = self.bridge.security_get_scan(request_id="widget-start-001")
        self.assertEqual(resolved["scanId"], started["scanId"])
        self.assertEqual(resolved["requestId"], "widget-start-001")
        self.bridge.db.execute(
            "UPDATE security_requests SET scan_id=NULL,status='pending' WHERE request_id=?",
            ("widget-start-001",),
        )
        self.bridge.db.commit()
        pending = self.bridge.security_get_scan(request_id="widget-start-001")
        self.assertEqual(pending["status"], "pending")
        self.assertIn("do not call security_start_scan", pending["phaseInstructions"])
        with self.assertRaisesRegex(BridgeError, "exactly one"):
            self.bridge.security_get_scan()
        with self.assertRaisesRegex(BridgeError, "exactly one"):
            self.bridge.security_get_scan(started["scanId"], "widget-start-001")

    def test_commit_timeout_is_recoverable_and_retry_is_idempotent(self):
        adapter = TimeoutCommitSecurityAdapter(self.root)
        bridge = self.new_bridge("timeout-state", adapter)
        try:
            started = bridge.security_start_scan("standard", "codebase", request_id="timeout-start-001")
            with self.assertRaisesRegex(BridgeError, "SECURITY_RUNTIME_TIMEOUT"):
                bridge.security_commit_phase(
                    started["scanId"], "preflight", request_id="timeout-phase-001",
                    coverage={"files": 1}
                )

            native_calls = list(adapter.calls)
            recovered = bridge.security_get_scan(started["scanId"])
            self.assertTrue(recovered["recoveryRequired"])
            self.assertEqual(recovered["recoveryRequestId"], "timeout-phase-001")
            self.assertEqual(recovered["phase"], "preflight")
            self.assertEqual(adapter.calls, native_calls)

            retried = bridge.security_commit_phase(
                started["scanId"], "preflight", request_id="timeout-phase-001", coverage={"files": 1}
            )
            self.assertEqual(retried["phase"], "inventory")
            self.assertEqual(retried["committedPhase"], "preflight")
            self.assertFalse(retried["recoveryRequired"])
            self.assertEqual(len([call for call in adapter.calls if isinstance(call, tuple) and call[0] == "commit_phase"]), 1)
            self.assertEqual(retried["phaseHistory"][0]["requestId"], "timeout-phase-001")
        finally:
            bridge.close()

    def test_start_timeout_blocks_new_scan_and_retries_without_duplicate(self):
        adapter = TimeoutStartSecurityAdapter(self.root)
        bridge = self.new_bridge("timeout-start-state", adapter)
        try:
            with self.assertRaisesRegex(BridgeError, "SECURITY_RUNTIME_TIMEOUT"):
                bridge.security_start_scan("standard", "codebase", request_id="timeout-start-001")
            with self.assertRaisesRegex(BridgeError, "SECURITY_SCAN_ACTIVE"):
                bridge.security_start_scan("standard", "codebase", request_id="other-start-001")
            retry = bridge.security_start_scan("standard", "codebase", request_id="timeout-start-001")
            self.assertEqual(retry["scanId"], "scan-0001")
            self.assertEqual(len(adapter.start_calls), 1)
        finally:
            bridge.close()

    def test_safe_findings_export_panel_and_terminal_cancel_idempotency(self):
        started = self.bridge.security_start_scan("standard", "codebase", request_id="safe-001")
        findings = self.bridge.security_list_findings(started["scanId"])
        self.assertEqual(findings["findings"][0]["file"], "src/app.py")
        self.assertEqual(findings["findings"][0]["startLine"], 91)
        self.assertEqual(findings["findings"][0]["locations"][1]["file"], "src/config.py")
        self.assertNotIn("private-token", json.dumps(findings).lower())
        exported = self.bridge.security_export_findings(started["scanId"], "json")
        self.assertNotIn("private-token", json.dumps(exported))
        self.assertNotIn(str(self.root), json.dumps(exported))
        panel = self.bridge.show_security_scan_panel()
        self.assertEqual(panel["panel"], "security-scan-v1")
        self.assertEqual(panel["supportedReviewModes"], ["standard", "chatgpt_deep"])
        self.assertNotIn(str(self.root), json.dumps(panel))

        cancelled = self.bridge.security_cancel_scan(started["scanId"], "cancel-001")
        self.assertEqual(cancelled["status"], "cancelled")
        repeated = self.bridge.security_cancel_scan(started["scanId"], "cancel-001")
        self.assertEqual(repeated["status"], "cancelled")
        with self.assertRaisesRegex(BridgeError, "SECURITY_TERMINAL"):
            self.bridge.security_complete_scan(started["scanId"], "complete-after-cancel")


if __name__ == "__main__":
    unittest.main()

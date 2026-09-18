"""Import-safe contract tests for the public Security MCP facade."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))

import server
from files import BridgeError


SECURITY_TOOLS = {
    "show_security_scan_panel",
    "security_start_scan",
    "security_get_scan",
    "security_continue_scan",
    "security_commit_phase",
    "security_complete_scan",
    "security_cancel_scan",
    "security_list_findings",
    "security_export_findings",
}
LEGACY_TOOLS = {
    "show_control_panel",
    "list_files",
    "read_file",
    "write_file",
    "apply_patch",
    "git_diff",
    "run_task",
    "set_runtime_mode",
    "run_bash",
    "project_info",
    "search_code",
    "prepare_changes",
    "list_changes",
    "get_change",
    "apply_changes",
    "undo_changes",
    "list_tasks",
    "start_task",
    "get_task_run",
    "stop_task_run",
    "list_skills",
    "read_skill",
    "read_skill_resource",
    "list_codex_threads",
    "read_codex_thread",
    "codex_docs_search",
    "codex_docs_fetch",
}
DIAGNOSTIC_TOOLS = {"mcp_diagnostics"}


class FakeBridge:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def project_info(self):
        return {
            "workspace_root": "C:/project",
            "runtime": {
                "status": "connected",
                "version": "test",
                "error": None,
                "mode": "normal",
                "mode_description": "Normal",
                "commands_enabled": True,
                "bash_enabled": False,
                "command_error": None,
            },
            "capabilities": {"tasks": True},
        }

    def _record(self, name: str, **kwargs):
        self.calls.append((name, kwargs))

    def show_security_scan_panel(self):
        self._record("show_security_scan_panel")
        return {"supportedTargets": ["codebase", "changes"], "activeScan": None, "latestScan": None}

    def security_start_scan(self, **kwargs):
        self._record("security_start_scan", **kwargs)
        return {
            "scanId": "scan-1",
            "reviewMode": kwargs["review_mode"],
            "target": kwargs["target"],
            "status": "running",
            "phase": "preflight",
            "nextPhase": "inventory",
            "updatedAt": "2026-09-16T00:00:00Z",
        }

    def security_get_scan(self, **kwargs):
        self._record("security_get_scan", **kwargs)
        return {"scanId": kwargs["scan_id"], "status": "running", "currentPhase": "preflight"}

    def security_continue_scan(self, **kwargs):
        self._record("security_continue_scan", **kwargs)
        return {"scanId": kwargs["scan_id"], "currentPhase": "preflight", "nextPhase": "inventory"}

    def security_commit_phase(self, **kwargs):
        self._record("security_commit_phase", **kwargs)
        return {"scanId": kwargs["scan_id"], "phase": kwargs["phase"], "status": "running"}

    def security_complete_scan(self, **kwargs):
        self._record("security_complete_scan", **kwargs)
        return {"scanId": kwargs["scan_id"], "status": "completed"}

    def security_cancel_scan(self, **kwargs):
        self._record("security_cancel_scan", **kwargs)
        return {"scanId": kwargs["scan_id"], "status": "cancelled"}

    def security_list_findings(self, **kwargs):
        self._record("security_list_findings", **kwargs)
        return {"scanId": kwargs["scan_id"], "findings": [], "nextCursor": None}

    def security_export_findings(self, **kwargs):
        self._record("security_export_findings", **kwargs)
        return {"scanId": kwargs["scan_id"], "format": kwargs["format"], "content": "[]"}


class FakeTaskBridge(FakeBridge):
    def __init__(self):
        super().__init__()
        self.task_status = "running"

    def security_task_snapshot(self, scan_id):
        return {
            "scanId": scan_id,
            "status": self.task_status,
            "phase": "complete" if self.task_status == "completed" else "preflight",
            "currentPhase": "complete" if self.task_status == "completed" else "preflight",
            "nextPhase": None if self.task_status == "completed" else "inventory",
            "updatedAt": "2026-09-18T00:00:02Z",
        }, 1.0, 2.0

    def security_cancel_scan(self, **kwargs):
        self._record("security_cancel_scan", **kwargs)
        self.task_status = "cancelled"
        return {"scanId": kwargs["scan_id"], "status": "cancelled"}


class SecurityServerTests(unittest.TestCase):
    def setUp(self):
        self.previous_bridge = server._bridge
        self.fake = FakeBridge()
        server._bridge = self.fake

    def tearDown(self):
        server._bridge = self.previous_bridge

    def test_security_scan_uses_mcp_task_lifecycle(self):
        fake = FakeTaskBridge()
        previous_bridge = server._bridge
        server._bridge = fake
        try:
            ctx = SimpleNamespace(
                protocol_version="2026-07-28",
                session=SimpleNamespace(
                    client_capabilities=SimpleNamespace(
                        extensions={server.TASKS_EXTENSION_ID: {}}
                    )
                ),
            )
            params = SimpleNamespace(
                name="security_start_scan",
                arguments={
                    "review_mode": "standard",
                    "target": "codebase",
                    "request_id": "security-task-001",
                },
            )

            async def call_next(_ctx):
                return server.CallToolResult(
                    content=[server.TextContent(type="text", text="started")],
                    structured_content={"scanId": "scan-1", "status": "running"},
                )

            created = asyncio.run(server.MCPTasksExtension().intercept_tool_call(params, ctx, call_next))
            self.assertEqual(created["resultType"], "task")
            self.assertEqual(created["taskId"], "security:scan-1")
            running = asyncio.run(
                server._mcp_tasks_get(ctx, server.MCPTaskGetParams(task_id="security:scan-1"))
            )
            self.assertEqual(running["status"], "working")

            fake.task_status = "completed"
            completed = asyncio.run(
                server._mcp_tasks_get(ctx, server.MCPTaskGetParams(task_id="security:scan-1"))
            )
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["result"]["structuredContent"]["status"], "completed")

            fake.task_status = "running"
            self.assertEqual(
                asyncio.run(
                    server._mcp_tasks_cancel(ctx, server.MCPTaskCancelParams(task_id="security:scan-1"))
                ),
                {"resultType": "complete"},
            )
            self.assertEqual(fake.task_status, "cancelled")
        finally:
            server._bridge = previous_bridge

    def test_tools_list_schema_and_surface(self):
        tools = asyncio.run(server.mcp.list_tools())
        by_name = {tool.name: tool for tool in tools}
        self.assertTrue(SECURITY_TOOLS <= by_name.keys())
        self.assertTrue(LEGACY_TOOLS <= by_name.keys())
        self.assertTrue(DIAGNOSTIC_TOOLS <= by_name.keys())

        serialized = json.dumps(
            [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "schema": tool.input_schema,
                    "meta": tool.meta,
                }
                for tool in tools
            ],
            ensure_ascii=True,
        )
        for forbidden in (
            "native_deep",
            "start_codex_security_deep_scan",
            "CodexSdkWorkerExecutor",
            "reasoningEffort",
        ):
            self.assertNotIn(forbidden, serialized)

        start_schema = by_name["security_start_scan"].input_schema
        self.assertEqual(
            start_schema["properties"]["review_mode"]["enum"],
            ["standard", "chatgpt_deep"],
        )
        self.assertEqual(start_schema["properties"]["target"]["enum"], ["codebase", "changes"])
        self.assertEqual(set(start_schema["required"]), {"review_mode", "target", "request_id"})
        self.assertEqual(by_name["security_start_scan"].meta["ui"]["visibility"], ["app"])
        self.assertEqual(by_name["show_security_scan_panel"].meta["ui"]["visibility"], ["model", "app"])
        self.assertIn("only shows the chooser", by_name["show_security_scan_panel"].description)
        self.assertIn("Never call it directly", by_name["security_start_scan"].description)

        get_schema = by_name["security_get_scan"].input_schema
        self.assertEqual(set(get_schema["properties"]), {"scan_id", "request_id"})
        self.assertNotIn("required", get_schema)

        commit_schema = by_name["security_commit_phase"].input_schema
        request_schema = commit_schema["properties"]["request"]
        self.assertIn("oneOf", request_schema)
        self.assertEqual(request_schema["discriminator"]["propertyName"], "phase")
        self.assertNotIn("payload", json.dumps(commit_schema))

        for name in SECURITY_TOOLS:
            self.assertTrue(by_name[name].output_schema)
            self.assertTrue(by_name[name].meta["openai/widgetAccessible"])
        for name in SECURITY_TOOLS | LEGACY_TOOLS | DIAGNOSTIC_TOOLS:
            schema = by_name[name].output_schema
            self.assertIn("anyOf", schema)
            self.assertIn("ErrorEnvelope", schema.get("$defs", {}))
            self.assertIn("error_code", schema["$defs"]["ErrorEnvelope"]["properties"])
        self.assertEqual(by_name["show_security_scan_panel"].meta["ui"]["resourceUri"], server.SECURITY_UI_URI)
        for name in SECURITY_TOOLS - {"show_security_scan_panel"}:
            self.assertNotIn("resourceUri", by_name[name].meta["ui"])

    def test_mcp_diagnostics_is_typed_and_safe(self):
        result = asyncio.run(server.mcp.call_tool("mcp_diagnostics", {}))

        self.assertFalse(result.is_error)
        payload = server.MCPDiagnosticsResponse.model_validate(result.structured_content)
        self.assertEqual(payload.status, "ok")
        self.assertEqual(payload.protocol_version, "unknown")
        self.assertEqual(payload.resource_uri, server.UI_URI)
        self.assertTrue(payload.apps_support)
        self.assertTrue(payload.subscriptions_support)
        self.assertTrue(payload.structured_output_support)
        self.assertEqual(payload.current_project, "C:/project")
        serialized = json.dumps(payload.model_dump(mode="json"), ensure_ascii=True).lower()
        for forbidden in ("token", "authorization", "password", "secret", "credential", ".env"):
            self.assertNotIn(forbidden, serialized)

    def test_resources_remain_separate(self):
        security = list(asyncio.run(server.mcp.read_resource(server.SECURITY_UI_URI)))[0]
        control = list(asyncio.run(server.mcp.read_resource(server.UI_URI)))[0]
        self.assertEqual(security.mime_type, "text/html;profile=mcp-app")
        self.assertIn("security-scan-v1", security.content)
        self.assertIn("Security MCP App", security.content)
        self.assertIn("--accent: #f1c21b", security.content)
        self.assertIn("--font-mono:", security.content)
        self.assertIn("Codex Bridge Control Center", control.content)
        self.assertNotEqual(server.SECURITY_UI_URI, server.UI_URI)

    def test_public_tools_return_structured_content(self):
        async def exercise():
            calls = [
                ("show_security_scan_panel", {}),
                (
                    "security_start_scan",
                    {"review_mode": "standard", "target": "codebase", "request_id": "req-1"},
                ),
                ("security_get_scan", {"scan_id": "scan-1"}),
                ("security_continue_scan", {"scan_id": "scan-1"}),
                (
                    "security_commit_phase",
                    {
                        "request": {
                            "scan_id": "scan-1",
                            "request_id": "req-2",
                            "phase": "discovery",
                            "candidates": [],
                        }
                    },
                ),
                ("security_complete_scan", {"scan_id": "scan-1", "request_id": "req-3"}),
                ("security_cancel_scan", {"scan_id": "scan-1", "request_id": "req-4"}),
                ("security_list_findings", {"scan_id": "scan-1"}),
                ("security_export_findings", {"scan_id": "scan-1", "format": "json"}),
            ]
            return [await server.mcp.call_tool(name, args) for name, args in calls]

        results = asyncio.run(exercise())
        self.assertEqual(len(results), len(SECURITY_TOOLS))
        self.assertTrue(all(isinstance(result.structured_content, dict) for result in results))
        self.assertEqual(self.fake.calls[1][0], "security_start_scan")
        self.assertEqual(self.fake.calls[1][1]["review_mode"], "standard")
        self.assertEqual(self.fake.calls[4][1]["phase"], "discovery")

    def test_deep_phase_schema_reaches_bridge(self):
        async def exercise():
            return await server.mcp.call_tool(
                "security_commit_phase",
                {"request": {
                    "scan_id": "scan-1",
                    "request_id": "deep-phase-1",
                    "phase": "attack_surface",
                    "candidates": [],
                    "coverage": {"surfaces": []},
                }},
            )

        result = asyncio.run(exercise())
        self.assertIsInstance(result.structured_content, dict)
        self.assertEqual(self.fake.calls[-1][1]["phase"], "attack_surface")

    def test_list_findings_maps_public_limit_name_to_bridge_limit(self):
        async def exercise():
            return await server.mcp.call_tool(
                "security_list_findings",
                {"scan_id": "scan-1", "cursor": "7", "max_results": 200},
            )

        result = asyncio.run(exercise())
        self.assertIsInstance(result.structured_content, dict)
        self.assertEqual(
            self.fake.calls[-1],
            (
                "security_list_findings",
                {"scan_id": "scan-1", "cursor": "7", "limit": 200},
            ),
        )

    def test_inventory_schema_reaches_bridge(self):
        async def exercise():
            return await server.mcp.call_tool(
                "security_commit_phase",
                {"request": {
                    "scan_id": "scan-1",
                    "request_id": "inventory-phase-1",
                    "phase": "inventory",
                    "inventory": [{"path": "src/app.py"}],
                    "boundaries": [{"name": "web-to-service"}],
                    "coverage": {"files": 1},
                }},
            )

        result = asyncio.run(exercise())
        self.assertIsInstance(result.structured_content, dict)
        self.assertEqual(self.fake.calls[-1][1]["phase"], "inventory")

    def test_bridge_errors_are_structured_and_keep_legacy_debug_text(self):
        class ErrorBridge(FakeBridge):
            def list_files(self, *_args):
                raise BridgeError("SHA_CONFLICT: src/app.py, src/lib.py")

        previous = server._bridge
        server._bridge = ErrorBridge()
        try:
            result = asyncio.run(server.mcp.call_tool("list_files", {"prefix": ""}))
        finally:
            server._bridge = previous

        self.assertTrue(result.is_error)
        self.assertEqual(result.structured_content["status"], "error")
        self.assertEqual(result.structured_content["error_code"], "SHA_MISMATCH")
        self.assertEqual(result.structured_content["legacy_code"], "SHA_CONFLICT")
        self.assertEqual(result.structured_content["details"]["paths"], ["src/app.py", "src/lib.py"])
        self.assertEqual(result.structured_content["technical_message"], "SHA_CONFLICT: src/app.py, src/lib.py")

    def test_common_bridge_errors_have_stable_codes_and_retry_flags(self):
        cases = {
            "SHA_CONFLICT: a.py": ("SHA_MISMATCH", False),
            "CHANGE_STATE: expected prepared; found applied.": ("STALE_CHANGE", False),
            "IDEMPOTENCY_CONFLICT: request_id is reused.": ("IDEMPOTENCY_CONFLICT", False),
            "TASK_UNAVAILABLE: executable is missing.": ("TASK_UNAVAILABLE", False),
            "SANDBOX_UNAVAILABLE: disconnected.": ("SANDBOX_UNAVAILABLE", True),
            "PATH_BLOCKED: protected file.": ("PERMISSION_DENIED", False),
            "SECURITY_PHASE_ORDER: wrong phase.": ("SCAN_STATE_CONFLICT", False),
            "NOT_FOUND: unknown run_id.": ("NOT_FOUND", False),
        }

        class ErrorBridge(FakeBridge):
            error = ""

            def security_start_scan(self, **_kwargs):
                raise BridgeError(self.error)

        for technical, expected in cases.items():
            with self.subTest(technical=technical):
                previous = server._bridge
                error_bridge = ErrorBridge()
                error_bridge.error = technical
                server._bridge = error_bridge
                try:
                    result = asyncio.run(server.mcp.call_tool("security_start_scan", {
                        "review_mode": "standard",
                        "target": "codebase",
                        "request_id": "req-1",
                    }))
                finally:
                    server._bridge = previous
                payload = result.structured_content
                self.assertTrue(result.is_error)
                self.assertEqual((payload["error_code"], payload["retryable"]), expected)
                self.assertEqual(payload["request_id"], "req-1")
                self.assertEqual(payload["technical_message"], technical)

    def test_argument_validation_errors_are_structured(self):
        result = asyncio.run(server.mcp.call_tool("security_start_scan", {
            "review_mode": "native_deep",
            "target": "codebase",
            "request_id": "invalid-input-1",
        }))

        self.assertTrue(result.is_error)
        payload = result.structured_content
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "INVALID_INPUT")
        self.assertEqual(payload["request_id"], "invalid-input-1")
        self.assertIn("review_mode", payload["details"]["fields"])
        self.assertIn("validation error", payload["technical_message"])

    def test_unexpected_tool_errors_keep_the_cause_in_structured_output(self):
        class ErrorBridge(FakeBridge):
            def list_files(self, *_args):
                raise RuntimeError("adapter exploded")

        previous = server._bridge
        server._bridge = ErrorBridge()
        try:
            result = asyncio.run(server.mcp.call_tool("list_files", {}))
        finally:
            server._bridge = previous

        self.assertTrue(result.is_error)
        self.assertEqual(result.structured_content["error_code"], "INTERNAL_ERROR")
        self.assertEqual(result.structured_content["details"]["cause_type"], "RuntimeError")
        self.assertIn("adapter exploded", result.structured_content["technical_message"])

    def test_all_legacy_tools_return_typed_success_content(self):
        project = {
            "workspace_root": "C:/project",
            "git_available": True,
            "git_repository": True,
            "runtime": {
                "status": "connected",
                "version": "test",
                "error": None,
                "mode": "normal",
                "mode_description": "Normal",
                "commands_enabled": True,
                "bash_enabled": False,
                "command_error": None,
            },
            "capabilities": {
                "changes": True,
                "read_file": True,
                "control_panel": True,
                "search": True,
                "tasks": True,
                "bash": True,
                "watch": True,
                "skills": True,
                "history": True,
                "docs": True,
            },
            "approved_tasks": ["sample"],
            "active_run_id": None,
            "revision": 1,
            "recovery_conflicts": [],
        }
        change = {
            "change_id": "change-1",
            "title": "Test change",
            "status": "prepared",
            "error": None,
            "files": [{
                "path": "a.txt",
                "before_sha256": "a",
                "after_sha256": "b",
                "created": False,
            }],
            "diff": "",
            "next_offset": None,
        }
        run = {
            "run_id": "run-1",
            "task_id": "sample",
            "status": "succeeded",
            "elapsed_seconds": 0.1,
            "exit_code": 0,
            "error": None,
            "events": [{"stream": "stdout", "text": "ok\n"}],
            "next_cursor": 1,
            "logs_available": True,
            "truncated": False,
            "stopping": False,
            "timed_out": False,
        }

        class Tasks:
            def list_tasks(self):
                return {"tasks": [{"task_id": "sample", "command": ["sample"]}],
                        "available": True, "unavailable_reason": None, "active_run_id": None}

            def start_task(self, *_args, **_kwargs):
                return run

            def get_task_run(self, *_args, **_kwargs):
                return run

            def stop_task_run(self, *_args, **_kwargs):
                return run

            def run_task(self, *_args, **_kwargs):
                return {**run, "stdout": "ok\n", "stderr": "", "command": ["sample"]}

        class LegacyBridge:
            tasks = Tasks()

            def show_control_panel(self):
                return {"panel_available": True, "project": project, "changes": [],
                        "task_state": self.tasks.list_tasks()}

            def list_files(self, *_args, **_kwargs):
                return {"workspace_root": "C:/project", "files": ["a.txt"], "truncated": False}

            def read_file(self, *_args, **_kwargs):
                return {"path": "a.txt", "sha256": "a", "content": "old\n", "start_line": 1,
                        "end_line": 1, "total_lines": 1, "partial_last_line": False,
                        "next_line": None, "truncated": False}

            def write_file(self, *_args, **_kwargs):
                return {"path": "a.txt", "sha256": "b", "bytes_written": 4,
                        "change_id": "change-1", "status": "applied"}

            def apply_patch(self, *_args, **_kwargs):
                return {"path": "a.txt", "sha256": "b", "change_id": "change-1", "status": "applied"}

            def git_diff(self, *_args, **_kwargs):
                return {"path": None, "exit_code": 0, "diff": "", "stderr": "", "truncated": False}

            def set_runtime_mode(self, *_args, **_kwargs):
                return {"mode": "normal", "project": project}

            def run_bash(self, *_args, **_kwargs):
                return {"mode": "turbo", "exit_code": 0, "stdout": "ok\n", "stderr": "", "truncated": False}

            def project_info(self):
                return project

            def search_code(self, *_args, **_kwargs):
                return {"matches": [], "next_cursor": None, "inventory_truncated": False,
                        "output_truncated": False, "hint": "none"}

            def prepare_changes(self, *_args, **_kwargs):
                return change

            def list_changes(self, *_args, **_kwargs):
                return {"changes": []}

            def get_change(self, *_args, **_kwargs):
                return change

            def apply_changes(self, *_args, **_kwargs):
                return {**change, "status": "applied"}

            def undo_changes(self, *_args, **_kwargs):
                return {**change, "status": "undone"}

            def list_skills(self):
                return {"skills": [], "instruction": "guidance only"}

            def read_skill(self, *_args, **_kwargs):
                return {"path": "SKILL.md", "sha256": "a", "content": "text", "start_line": 1,
                        "end_line": 1, "total_lines": 1, "partial_last_line": False,
                        "next_line": None, "truncated": False}

            def read_skill_resource(self, *_args, **_kwargs):
                return {"path": "ref.md", "sha256": "a", "content": "text", "start_line": 1,
                        "end_line": 1, "total_lines": 1, "partial_last_line": False,
                        "next_line": None, "truncated": False}

            def list_codex_threads(self, *_args, **_kwargs):
                return {"threads": [], "next_cursor": None}

            def read_codex_thread(self, *_args, **_kwargs):
                return {"thread_id": "thread-1", "turns": [], "next_turn": None, "note": "text only"}

            def codex_docs_search(self, *_args, **_kwargs):
                return {"result": {"items": []}}

            def codex_docs_fetch(self, *_args, **_kwargs):
                return {"result": {"content": "doc"}}

        calls = [
            ("show_control_panel", {}),
            ("list_files", {}),
            ("read_file", {"path": "a.txt"}),
            ("write_file", {"path": "a.txt", "content": "new"}),
            ("apply_patch", {"path": "a.txt", "old_text": "old", "new_text": "new", "expected_sha256": "a"}),
            ("git_diff", {}),
            ("run_task", {"task_id": "sample", "timeout_seconds": 1}),
            ("set_runtime_mode", {"mode": "normal"}),
            ("run_bash", {"command": "echo hi", "timeout_seconds": 1}),
            ("project_info", {}),
            ("search_code", {"query": "x"}),
            ("prepare_changes", {"title": "x", "edits": [{"path": "a.txt", "content": "new"}], "request_id": "req-1"}),
            ("list_changes", {}),
            ("get_change", {"change_id": "change-1"}),
            ("apply_changes", {"change_id": "change-1", "request_id": "req-2"}),
            ("undo_changes", {"change_id": "change-1", "request_id": "req-3"}),
            ("list_tasks", {}),
            ("start_task", {"task_id": "sample", "request_id": "req-4", "timeout_seconds": 1}),
            ("get_task_run", {"run_id": "run-1"}),
            ("stop_task_run", {"run_id": "run-1", "request_id": "req-5"}),
            ("list_skills", {}),
            ("read_skill", {"skill_id": "skill-1"}),
            ("read_skill_resource", {"skill_id": "skill-1", "path": "ref.md"}),
            ("list_codex_threads", {}),
            ("read_codex_thread", {"thread_id": "thread-1"}),
            ("codex_docs_search", {"query": "MCP"}),
            ("codex_docs_fetch", {"url": "https://developers.openai.com/docs"}),
        ]
        previous = server._bridge
        server._bridge = LegacyBridge()
        try:
            async def exercise():
                return [await server.mcp.call_tool(name, args) for name, args in calls]

            results = asyncio.run(exercise())
        finally:
            server._bridge = previous

        self.assertEqual(len(results), len(calls))
        self.assertTrue(all(not result.is_error for result in results))
        self.assertTrue(all(isinstance(result.structured_content, dict) for result in results))
        self.assertTrue(all("status" in result.structured_content for result in results))


def run_tests():
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SecurityServerTests)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()

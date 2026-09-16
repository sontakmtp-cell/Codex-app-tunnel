"""Import-safe contract tests for the public Security MCP facade."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))

import server


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


class FakeBridge:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

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


class SecurityServerTests(unittest.TestCase):
    def setUp(self):
        self.previous_bridge = server._bridge
        self.fake = FakeBridge()
        server._bridge = self.fake

    def tearDown(self):
        server._bridge = self.previous_bridge

    def test_tools_list_schema_and_surface(self):
        tools = asyncio.run(server.mcp.list_tools())
        by_name = {tool.name: tool for tool in tools}
        self.assertTrue(SECURITY_TOOLS <= by_name.keys())
        self.assertTrue(LEGACY_TOOLS <= by_name.keys())

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
        self.assertEqual(by_name["show_security_scan_panel"].meta["ui"]["resourceUri"], server.SECURITY_UI_URI)
        for name in SECURITY_TOOLS - {"show_security_scan_panel"}:
            self.assertNotIn("resourceUri", by_name[name].meta["ui"])

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


def run_tests():
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SecurityServerTests)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    run_tests()

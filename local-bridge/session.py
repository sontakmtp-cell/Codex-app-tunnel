"""One selected workspace; switching never overlaps an operation or a running task."""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import threading
import uuid

from bridge import LocalBridge
from files import BridgeError, ProjectFiles, _sha256, check_link_chain, load_config


class WorkspaceSession:
    def __init__(self, config_path, factory=LocalBridge):
        self.config_path = Path(config_path).resolve()
        self.default = load_config(self.config_path)
        self.factory = factory
        self.guard = threading.RLock()
        self.users = 0
        self.switching = False
        self.context_id = uuid.uuid4().hex
        self.selection = self.default.state_dir / "selection.json"
        self.recent = [str(self.default.workspace_root)]
        root = self.default.workspace_root
        if self.selection.is_file():
            saved = json.loads(self.selection.read_text(encoding="utf-8"))
            self.recent = saved.get("recent", self.recent)[:12]
            try:
                root = self._root(saved["workspace_root"])
            except (BridgeError, KeyError):
                root = self.default.workspace_root
        # Starting the bridge always begins in Normal. Only a panel action enables Turbo.
        self.current = self.factory(self._config(root, "normal"))

    def _root(self, value):
        if not isinstance(value, str) or not value or len(value) > 1000:
            raise BridgeError("INVALID_WORKSPACE: enter an absolute path to an existing local folder.")
        root = Path(value)
        if (not root.is_absolute() or not root.is_dir() or root == Path(root.anchor)
                or str(root).startswith("\\\\") or any(p in ("..", ".") for p in root.parts)):
            raise BridgeError("INVALID_WORKSPACE: select an existing local folder, not a drive or network share.")
        check_link_chain(root)
        root = root.resolve()
        protected = (Path(__file__).resolve(), self.config_path, self.selection, self.default.state_dir)
        if any(p.is_relative_to(root) for p in protected) or root.is_relative_to(self.default.state_dir):
            raise BridgeError("WORKSPACE_DENIED: the selected folder must not expose bridge code, configuration or journals to writes.")
        return root

    def _config(self, root, mode):
        if root == self.default.workspace_root:
            return replace(self.default, mode=mode, private_state_dir=self.default.state_dir)
        state = self.default.state_dir / "workspaces" / _sha256(os.path.normcase(str(root)).encode())[:16]
        # Project-specific build commands must never follow the user into another folder.
        return replace(self.default, workspace_root=root, state_dir=state, mode=mode, private_state_dir=self.default.state_dir,
                       tasks={"git_status": ("git", "status", "--short"), "git_diff_check": ("git", "diff", "--check")})

    @contextmanager
    def use(self, context_id=None, require_context=False):
        with self.guard:
            if self.switching:
                raise BridgeError("WORKSPACE_SWITCHING: wait for the selected workspace to finish opening.")
            if (require_context or context_id is not None) and context_id != self.context_id:
                raise BridgeError("CONTEXT_CHANGED: read project_info and pass its current context_id before writing or running tools.")
            self.users += 1
        try:
            yield self.current
        finally:
            with self.guard:
                self.users -= 1

    def info(self):
        return {**self.current.project_info(), "context_id": self.context_id,
                "recent_workspaces": list(dict.fromkeys([str(self.current.root), *self.recent]))[:12]}

    def switch(self, context_id, *, workspace_root=None, mode=None):
        if mode is not None and mode not in ("normal", "turbo"):
            raise BridgeError("INVALID_MODE: choose normal or turbo.")
        root = self._root(workspace_root) if workspace_root is not None else self.current.root
        with self.guard:
            if context_id != self.context_id:
                raise BridgeError("CONTEXT_CHANGED: refresh the panel before switching workspace or mode.")
            if self.switching or self.users or self.current.active_run:
                raise BridgeError("TASK_BUSY: wait for ongoing operations or stop the task before switching.")
            selected_mode = mode or self.current.config.mode
            if root == self.current.root and selected_mode == self.current.config.mode:
                return self.info()
            self.switching = True
        previous = self.current.config
        try:
            self.current.close()
            try:
                self.current = self.factory(self._config(root, selected_mode))
            except Exception:
                self.current = self.factory(previous)
                raise BridgeError("SWITCH_FAILED: previous workspace restored; no task was replayed.") from None
            self.context_id = uuid.uuid4().hex
            self.recent = list(dict.fromkeys([str(root), *self.recent]))[:12]
            ProjectFiles._atomic_write(self.selection, json.dumps({"workspace_root":str(root), "recent":self.recent}).encode())
            return self.info()
        finally:
            with self.guard:
                self.switching = False

    def close(self):
        self.current.close()

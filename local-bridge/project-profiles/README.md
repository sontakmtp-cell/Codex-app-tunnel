# Project task profiles

Task profiles live outside the selected project so ChatGPT cannot add or edit commands through the bridge.

Copy `TEMPLATE.json` to a new `.json` file, set its absolute `workspace_root`, then list the approved task argv and optional `${PROJECT_ROOT}` runtime roots. The bridge loads the profile whose `workspace_root` matches `project-path.txt`.

If no profile matches, file editing and the built-in Git tasks still work; project-specific tasks are simply unavailable.

After adding or changing a profile, run `start-chatgpt-coding-tunnel.ps1`; its fingerprint reloads the bridge when profile files change.

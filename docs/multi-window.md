# Several CodeBrowser windows

Each CodeBrowser window runs its own GhidraMCP backend. The first window listens on the
configured port (8080 by default). When that port is taken, usually by another CodeBrowser
window, the next window takes a free loopback port instead of failing.

Every backend writes `<port>.json` (port and Ghidra process ID) to the instance directory and
deletes it when its window closes:

- `$GHIDRA_MCP_INSTANCE_DIR`, if set (the bridge reads the same variable)
- otherwise `~/.ghidra_mcp/instances`

`/health` also reports `port` and `instance` (window name such as `CodeBrowser(2)`, project
name and process ID), so the bridge can tell windows apart.

## Bridge tools

In GUI mode the MCP server adds:

| Tool | Purpose |
| --- | --- |
| `list_ghidra_instances` | Live windows: port, window name, project, current program, and which one is selected |
| `select_ghidra_instance` | Change the default window for later calls, by port or unique name part |

Every other tool also takes an optional `instance` argument that targets one window for that
call only. It accepts a port, a loopback URL, or a case-insensitive substring of the window
name, program name, program path or project name that matches exactly one live window. An
ambiguous or unknown reference fails without calling any backend.

The selected default is shared by everything connected to one bridge process (for example
all Open WebUI chats on one streamable-http bridge, or parallel agents in one client). Agents
working on different windows at the same time should pass `instance` on each call instead of
switching the default.

Discovery probes the configured `--ghidra-server` URL and each registered port with a short
`/health` request and skips windows that do not answer, so files left behind by a crashed
Ghidra are ignored. Results are cached for two seconds. If the configured URL does not answer
at startup but another registered window does, the bridge starts with that window selected.

## Limits

- Windows that share one Ghidra process share its dialogs; `ghidra_dialogs` in any window
  lists all of them.
- Each window runs its own project job, so two windows can run scripts or analysis at once.
- The registry holds loopback ports only; remote Ghidra instances are still reached with
  `--ghidra-server`.

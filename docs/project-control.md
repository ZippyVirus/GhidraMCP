# Live GUI project control

The `project_control` capability adds these GUI tools:

| Tool | Purpose |
| --- | --- |
| `list_project_programs` | List project location, domain-file types and open status |
| `select_project_program` | Open/activate a program without manual tab navigation |
| `patch_program_bytes` | Apply a guarded batch in one transaction |
| `save_project_program` | Explicitly save a named program |
| `analyze_project_program` | Run the program's configured auto-analyzers |
| `run_project_script` | Run a registered script, including a project build/export action |
| `project_job` | Inspect the latest asynchronous job ID, state, result or error |
| `ghidra_dialogs` | Inspect visible dialog IDs, text and enabled buttons |
| `respond_to_ghidra_dialog` | Respond using a current ID and exact button label |

Mutating tools require the expected project name and, where applicable, an
absolute project program path. A different active project is rejected before
modification. These are live GUI programs, not headless copies. Opening suppresses
the first-open analysis prompt without marking the program analyzed. Run analysis
deliberately when wanted. The original inspection tools and headless mode remain
available; older GUI backends do not advertise the new tools.

Byte changes contain `address`, `old`, `new` and optional `disassemble`. Hex bytes
may contain spaces. Ranges, lengths, overlaps and expected bytes are validated
before any write; a rejected batch leaves earlier entries unchanged. Write
failures roll back. Instruction edits can request clearing and redisassembly;
data edits do not clear data definitions. Saving is explicit. `PROGRAM_BUSY`
means an active transaction prevents saving: wait and retry rather than force it.

Analysis and scripts run as one background job at a time. Poll the returned job
ID until complete or failed. Analysis reports function counts and readiness to
save; starting a job does not establish success. Analysis does not rebuild a
binary. Registered scripts can invoke an existing exporter/packer; no game
build logic or game-specific paths are embedded in the connector.

Scripts must be in registered Ghidra script directories. They have the full
authority of Ghidra and are not sandboxed. Run only trusted scripts within the
user's authorized scope. Existing loopback, Host and Origin checks apply to all
endpoints. Dialogs are not silently approved: inspect their text and explicitly
choose an enabled button using its current ID. Normal operations stay serialized
on a separate worker so HTTP workers can answer dialogs while normal work queues.

Validation is recorded in [project-control-validation.md](project-control-validation.md).
Current limits: GUI-only project control; one job at a time; no cancellation
endpoint; dialog buttons rather than arbitrary text/file chooser entry; no new
importer, memory allocator or binary/disc packer.

Build/install the Java extension and Python MCP package from the same branch.
A stock 2.0 GUI backend does not advertise these added tools.

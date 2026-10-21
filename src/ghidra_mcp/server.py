"""MCP tool definitions."""

from __future__ import annotations

import functools
import inspect
import json
from contextvars import ContextVar
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import Field

from ghidra_mcp.backend import BackendError, GhidraBackend
from ghidra_mcp.instances import InstanceSet, describe

CAP_GUI_CONTEXT = "gui_context"

PROJECT_CONTROL_TOOLS = (
    "list_project_programs", "select_project_program", "patch_program_bytes", "save_project_program",
    "analyze_project_program", "run_project_script", "project_job", "ghidra_dialogs", "respond_to_ghidra_dialog",
)

GUI_ONLY_TOOLS = ("get_current_address", "get_current_function")

INSTANCE_TOOLS = ("list_ghidra_instances", "select_ghidra_instance")

INSTRUCTIONS = """\
Tools for reverse engineering the program open in Ghidra. Call get_program_info first to confirm
which binary you are working on. Addresses are hex strings such as "0x401000". List tools are
paginated: pass offset/limit and check has_more. Prefer the address-based tools for modifications,
since function names can be ambiguous.
"""

INSTANCE_INSTRUCTIONS = """
Several CodeBrowser windows can be open at once. list_ghidra_instances shows them; pass
`instance` (a port, or a unique part of the window, program, or project name) to any tool to
target one window for that call, or use select_ghidra_instance to change the default.
"""

Result = dict[str, Any]

InstanceArg = Annotated[
    str | None,
    Field(description="Target CodeBrowser window: port, or a unique part of its window, program, "
                      "or project name (see list_ghidra_instances). Omit for the selected window."),
]


def create_server(
    backend: GhidraBackend,
    host: str = "127.0.0.1",
    port: int = 8081,
    capabilities: set[str] | None = None,
    instances: InstanceSet | None = None,
) -> FastMCP:
    """Builds the MCP server.

    `capabilities` comes from the backend's /health. When it is None (backend not reachable at
    startup) every tool is registered. With `instances` (GUI mode), every tool takes an optional
    `instance` argument and the window tools are added.
    """
    mcp = FastMCP("ghidra-mcp", instructions=INSTRUCTIONS + (INSTANCE_INSTRUCTIONS if instances else ""),
                  host=host, port=port)
    gui_context = capabilities is None or CAP_GUI_CONTEXT in capabilities
    # The window a tool call targets; set per call, so concurrent callers never share it.
    target: ContextVar[str | None] = ContextVar("ghidra_instance", default=None)

    def with_instance(fn):
        """Adds an optional `instance` argument that routes one call to another window."""
        sig = inspect.signature(fn, eval_str=True)
        extra = inspect.Parameter("instance", inspect.Parameter.KEYWORD_ONLY, default=None,
                                  annotation=InstanceArg)

        @functools.wraps(fn)
        def wrapper(*args, instance: str | None = None, **kwargs):
            token = target.set(instance)
            try:
                return fn(*args, **kwargs)
            finally:
                target.reset(token)

        wrapper.__signature__ = sig.replace(parameters=[*sig.parameters.values(), extra])
        return wrapper

    def tool():
        def register(fn):
            return mcp.tool()(with_instance(fn) if instances else fn)
        return register

    def call(method: str, endpoint: str, **params: Any) -> Any:
        try:
            ref = target.get()
            base_url = instances.resolve(ref) if ref and instances else None
            return backend.request(method, endpoint, params, base_url)
        except BackendError as e:
            raise ToolError(str(e)) from e

    def get(endpoint: str, **params: Any) -> Any:
        return call("GET", endpoint, **params)

    def post(endpoint: str, **params: Any) -> Any:
        return call("POST", endpoint, **params)

    # ---- Windows ---------------------------------------------------------------------------

    if instances:

        @mcp.tool()
        def list_ghidra_instances() -> Result:
            """List the open CodeBrowser windows reachable over MCP: port, window (tool) name,
            project, and current program. `selected` is the window tools use by default."""
            live = instances.discover(refresh=True)
            selected = backend.base_url
            for d in live:
                d["selected"] = d["url"] == selected
            return {"selected": selected, "instances": live}

        @mcp.tool()
        def select_ghidra_instance(instance: str) -> Result:
            """Make a window the default target for later tool calls in this MCP server, by
            port or by a unique substring of its window name, program, or project. Parallel
            agents should pass `instance` on each call instead, since this default is shared."""
            try:
                url = instances.resolve(instance)
                health = GhidraBackend(url).health()
            except BackendError as e:
                raise ToolError(str(e)) from e
            if health is None:
                raise ToolError(f"[BACKEND_UNAVAILABLE] No GhidraMCP backend answers at {url}")
            backend.base_url = url
            return describe(url, health)

    # ---- Program ---------------------------------------------------------------------------

    @tool()
    def get_program_info() -> Result:
        """Identify the target program: name, format, language/architecture, compiler spec,
        image base, address range, size, entry points, and hashes."""
        return get("program_info")

    # ---- Listings --------------------------------------------------------------------------

    @tool()
    def list_functions(offset: int = 0, limit: int = 100, filter: str | None = None) -> Result:
        """List functions (name and entry address), optionally filtered by a case-insensitive
        substring of the name."""
        return get("functions", offset=offset, limit=limit, filter=filter)

    @tool()
    def list_methods(offset: int = 0, limit: int = 100) -> list[str]:
        """Deprecated: use list_functions. Lists function names only."""
        page = get("functions", offset=offset, limit=limit)
        return [f["name"] for f in page["items"]]

    @tool()
    def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> Result:
        """Search for functions whose name contains the given substring (case-insensitive)."""
        if not query:
            raise ToolError("[MISSING_PARAMETER] query is required")
        return get("functions", offset=offset, limit=limit, filter=query)

    @tool()
    def list_classes(offset: int = 0, limit: int = 100) -> Result:
        """List class namespaces (fully qualified names)."""
        return get("classes", offset=offset, limit=limit)

    @tool()
    def list_namespaces(offset: int = 0, limit: int = 100) -> Result:
        """List all non-global namespaces (fully qualified names)."""
        return get("namespaces", offset=offset, limit=limit)

    @tool()
    def list_segments(offset: int = 0, limit: int = 100) -> Result:
        """List memory blocks with address range, size, and permissions."""
        return get("segments", offset=offset, limit=limit)

    @tool()
    def list_imports(offset: int = 0, limit: int = 100) -> Result:
        """List imported (external) symbols and their libraries."""
        return get("imports", offset=offset, limit=limit)

    @tool()
    def list_exports(offset: int = 0, limit: int = 100) -> Result:
        """List exported symbols / entry points."""
        return get("exports", offset=offset, limit=limit)

    @tool()
    def list_data_items(offset: int = 0, limit: int = 100) -> Result:
        """List defined data with address, label, type, and value."""
        return get("data", offset=offset, limit=limit)

    @tool()
    def list_strings(offset: int = 0, limit: int = 200, filter: str | None = None) -> Result:
        """List defined strings with their addresses, optionally filtered by a case-insensitive
        substring of the content."""
        return get("strings", offset=offset, limit=limit, filter=filter)

    # ---- Functions -------------------------------------------------------------------------

    @tool()
    def get_function_by_address(address: str) -> Result:
        """Get the function at or containing an address: name, signature, body range,
        calling convention."""
        return get("function", address=address)

    if gui_context:

        @tool()
        def get_current_address() -> Result:
            """Get the address currently selected in the Ghidra GUI listing."""
            return get("current_address")

        @tool()
        def get_current_function() -> Result:
            """Get the function containing the address currently selected in the Ghidra GUI."""
            return get("current_function")

    @tool()
    def decompile_function(name: str) -> Result:
        """Decompile a function by name and return C pseudocode. Fails if the name is ambiguous;
        use decompile_function_by_address in that case."""
        return get("decompile", name=name)

    @tool()
    def decompile_function_by_address(address: str) -> Result:
        """Decompile the function at or containing an address and return C pseudocode."""
        return get("decompile_function", address=address)

    @tool()
    def disassemble_function(address: str, offset: int = 0, limit: int = 500) -> Result:
        """Disassemble the instructions in a function's body (address, bytes, instruction,
        end-of-line comment)."""
        return get("disassemble_function", address=address, offset=offset, limit=limit)

    # ---- References ------------------------------------------------------------------------

    @tool()
    def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> Result:
        """List references to an address, with the function each reference comes from."""
        return get("xrefs_to", address=address, offset=offset, limit=limit)

    @tool()
    def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> Result:
        """List references from a single instruction or data address."""
        return get("xrefs_from", address=address, offset=offset, limit=limit)

    @tool()
    def get_function_xrefs(
        name: str | None = None, address: str | None = None, offset: int = 0, limit: int = 100
    ) -> Result:
        """List references to a function's entry point, by name or (preferably) address."""
        if not name and not address:
            raise ToolError("[MISSING_PARAMETER] name or address is required")
        return get("function_xrefs", name=name, address=address, offset=offset, limit=limit)

    @tool()
    def get_function_calls(
        address: str,
        direction: Literal["both", "callers", "callees"] = "both",
        offset: int = 0,
        limit: int = 100,
    ) -> Result:
        """Function-level call graph, one level deep. Callers are call sites that reach this
        function; callees are calls made from anywhere in its body, including indirect calls
        (direct=false). offset/limit apply to each list separately."""
        return get(
            "function_calls", address=address, direction=direction, offset=offset, limit=limit
        )

    # ---- Memory ----------------------------------------------------------------------------

    @tool()
    def read_memory(address: str, length: int = 64) -> Result:
        """Read up to 4096 bytes of program memory as hex and ASCII. Unmapped or uninitialized
        bytes are shown as '??' and listed in `gaps`."""
        return get("read_memory", address=address, length=length)

    # ---- Modifications ---------------------------------------------------------------------

    @tool()
    def rename_function_by_address(function_address: str, new_name: str) -> Result:
        """Rename the function at or containing an address."""
        return post(
            "rename_function_by_address", function_address=function_address, new_name=new_name
        )

    @tool()
    def rename_function(old_name: str, new_name: str) -> Result:
        """Rename a function by its current name. Fails if the name is ambiguous; prefer
        rename_function_by_address."""
        return post("rename_function", old_name=old_name, new_name=new_name)

    @tool()
    def rename_data(address: str, new_name: str) -> Result:
        """Rename the label of defined data (or an existing symbol) at an address."""
        return post("rename_data", address=address, new_name=new_name)

    @tool()
    def rename_variable(
        old_name: str,
        new_name: str,
        function_address: str | None = None,
        function_name: str | None = None,
    ) -> Result:
        """Rename a local variable or parameter as shown in the decompiler. Identify the function
        by function_address (preferred) or function_name."""
        if not function_address and not function_name:
            raise ToolError("[MISSING_PARAMETER] function_address or function_name is required")
        return post(
            "rename_variable",
            function_address=function_address,
            function_name=function_name,
            old_name=old_name,
            new_name=new_name,
        )

    @tool()
    def set_function_prototype(function_address: str, prototype: str) -> Result:
        """Set a function's signature from a C prototype, e.g. "int foo(char *buf, int len)"."""
        return post("set_function_prototype", function_address=function_address, prototype=prototype)

    @tool()
    def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> Result:
        """Set the data type of a decompiler variable, e.g. "char *", "DWORD", "MY_STRUCT *"."""
        return post(
            "set_local_variable_type",
            function_address=function_address,
            variable_name=variable_name,
            new_type=new_type,
        )

    @tool()
    def set_decompiler_comment(address: str, comment: str) -> Result:
        """Set the pre-comment at an address (shown in the decompiler). An empty comment clears
        it."""
        return post("set_decompiler_comment", address=address, comment=comment)

    @tool()
    def set_disassembly_comment(address: str, comment: str) -> Result:
        """Set the end-of-line comment at an address (shown in the disassembly). An empty comment
        clears it."""
        return post("set_disassembly_comment", address=address, comment=comment)

    if capabilities is None or "project_control" in capabilities:

        @tool()
        def list_project_programs() -> Result:
            """List domain files/programs in the live GUI project, open status, and active job."""
            return get("project")

        @tool()
        def select_project_program(project: str, path: str) -> Result:
            """Open/activate an absolute project program path without manual tab navigation.
            The project name must match. First-open analysis prompts are suppressed,
            without claiming analysis has run. Confirm get_program_info afterwards."""
            return post("select_program", project=project, path=path)

        @tool()
        def patch_program_bytes(project: str, path: str, changes: list[dict[str, Any]]) -> Result:
            """Apply one guarded Ghidra transaction. Each change has address, old/new hex,
            and optional disassemble boolean. All expected bytes and ranges must pass
            before any edit; failures roll back. Does not automatically save."""
            return post("patch_bytes", project=project, path=path, changes=json.dumps(changes))

        @tool()
        def save_project_program(project: str, path: str) -> Result:
            """Save the named program in the expected live GUI project."""
            return post("save_program", project=project, path=path)

        @tool()
        def analyze_project_program(project: str, path: str) -> Result:
            """Start auto-analysis using the program's configured analyzers. Poll project_job.
            Preserves existing analysis; results remain unsaved until explicitly saved."""
            return post("project_action", project=project, path=path, action="analyze")

        @tool()
        def run_project_script(project: str, script_path: str, arguments: list[str] | None = None) -> Result:
            """Run a script from a registered Ghidra script directory in the live GUI project.
            Poll project_job for completion/logs. A script can invoke project-specific
            build/export actions and has the full authority of the Ghidra process.
            Only run trusted scripts within the user's authorized task scope."""
            return post("project_action", project=project, action="script", script_path=script_path,
                        arguments=json.dumps(arguments or []))

        @tool()
        def project_job() -> Result:
            """Get the latest analysis/script job ID, state, result or error. One job at a time."""
            return get("project_job")

        @tool()
        def ghidra_dialogs() -> Result:
            """Inspect visible Ghidra dialog IDs, titles, text, and enabled buttons."""
            return get("dialogs")

        @tool()
        def respond_to_ghidra_dialog(project: str, id: str, button: str) -> Result:
            """Respond to an inspected Ghidra dialog using its current ID and exact button.
            Does not accept arbitrary window targets or silently approve every dialog.
            Respect the user's authorization for the action the button triggers."""
            return post("respond_dialog", project=project, id=id, button=button)

    return mcp

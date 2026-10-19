import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.backend import GhidraBackend
from ghidra_mcp.server import PROJECT_CONTROL_TOOLS, create_server


@pytest.mark.parametrize("capabilities", [None, {"gui_context", "project_control"}])
def test_project_tools_advertised_for_capable_or_unknown_backend(capabilities):
    server = create_server(GhidraBackend(), capabilities=capabilities)
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert set(PROJECT_CONTROL_TOOLS) <= names


@pytest.mark.parametrize("capabilities", [set(), {"gui_context"}])
def test_project_tools_hidden_for_headless_and_older_gui_backend(capabilities):
    server = create_server(GhidraBackend(), capabilities=capabilities)
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert not set(PROJECT_CONTROL_TOOLS) & names


@pytest.mark.parametrize("tool,endpoint,arguments,expected", [
    ("list_project_programs", "/project", {}, {}),
    ("select_project_program", "/select_program", {"project": "Research", "path": "/Overlays/Menu"},
     {"project": "Research", "path": "/Overlays/Menu"}),
    ("save_project_program", "/save_program", {"project": "Research", "path": "/main"},
     {"project": "Research", "path": "/main"}),
    ("analyze_project_program", "/project_action", {"project": "Research", "path": "/main"},
     {"project": "Research", "path": "/main", "action": "analyze"}),
    ("project_job", "/project_job", {}, {}),
    ("ghidra_dialogs", "/dialogs", {}, {}),
    ("respond_to_ghidra_dialog", "/respond_dialog", {"project": "Research", "id": "abc", "button": "No (Don't ask again)"},
     {"project": "Research", "id": "abc", "button": "No (Don't ask again)"}),
])
def test_project_tools_forward_identity_and_arguments(fake_backend, tool, endpoint, arguments, expected):
    fake_backend.ok(endpoint, {"state": "ok"})
    server = create_server(GhidraBackend(fake_backend.url), capabilities={"project_control"})
    asyncio.run(server.call_tool(tool, arguments))
    method, path, params = fake_backend.requests[-1]
    assert path == endpoint
    assert params == expected
    assert method == ("GET" if not expected else "POST")


def test_byte_batch_is_encoded_as_one_transaction(fake_backend):
    fake_backend.ok("/patch_bytes", {"changes": 2, "saved": False})
    server = create_server(GhidraBackend(fake_backend.url))
    changes = [{"address": "80010000", "old": "00 00", "new": "01 00", "disassemble": True},
               {"address": "80010010", "old": "ff", "new": "ab"}]
    asyncio.run(server.call_tool("patch_program_bytes", {"project": "Research", "path": "/main", "changes": changes}))
    params = fake_backend.requests[-1][2]
    assert params["project"] == "Research" and params["path"] == "/main"
    assert json.loads(params["changes"]) == changes


def test_script_arguments_preserve_spaces_quotes_and_newlines(fake_backend):
    fake_backend.ok("/project_action", {"state": "running", "id": "job-1"})
    server = create_server(GhidraBackend(fake_backend.url))
    args = ["C:/a project", 'literal "quote"', "line1\nline2"]
    asyncio.run(server.call_tool("run_project_script", {
        "project": "Research", "script_path": "C:/my scripts/Build.java", "arguments": args,
    }))
    params = fake_backend.requests[-1][2]
    assert params["action"] == "script"
    assert params["script_path"] == "C:/my scripts/Build.java"
    assert json.loads(params["arguments"]) == args


def test_backend_guard_failure_remains_an_error(fake_backend):
    fake_backend.fail("/patch_bytes", 409, "EXPECTED_BYTES_MISMATCH", "Nothing changed")
    server = create_server(GhidraBackend(fake_backend.url))
    with pytest.raises(ToolError, match="EXPECTED_BYTES_MISMATCH"):
        asyncio.run(server.call_tool("patch_program_bytes", {
            "project": "Research", "path": "/main", "changes": [{"address": "1", "old": "00", "new": "01"}],
        }))

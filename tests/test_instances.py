import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from ghidra_mcp.backend import BackendError, GhidraBackend
from ghidra_mcp.instances import INSTANCE_DIR_ENV, InstanceSet, registered_urls
from ghidra_mcp.server import INSTANCE_TOOLS, create_server

from conftest import FakeBackend


def health(tool, program, project="Studio"):
    return {"status": "ok", "mode": "gui", "capabilities": ["gui_context", "project_control"],
            "instance": {"tool": tool, "project": project, "pid": 1},
            "program": {"name": program, "project_path": "/" + program, "language_id": "MIPS"}}


@pytest.fixture
def windows(tmp_path, monkeypatch):
    """Two fake CodeBrowser backends; only the second is in the registry, like a window that
    fell back to a free port."""
    monkeypatch.setenv(INSTANCE_DIR_ENV, str(tmp_path))
    first, second = FakeBackend(), FakeBackend()
    first.ok("/health", health("CodeBrowser", "SCUS_944.62"))
    second.ok("/health", health("CodeBrowser(2)", "OVERLAY_MENU"))
    for fake, name in ((first, "main"), (second, "menu")):
        fake.ok("/program_info", {"name": name})
    port = second.server.server_address[1]
    (tmp_path / f"{port}.json").write_text(json.dumps({"port": port, "pid": 1}))
    yield first, second
    first.close()
    second.close()


def call(mcp, tool, **args):
    result = asyncio.run(mcp.call_tool(tool, args))
    return result[1] if isinstance(result, tuple) else json.loads(result[0].text)


def server_for(first):
    backend = GhidraBackend(first.url)
    return create_server(backend, capabilities={"gui_context", "project_control"},
                         instances=InstanceSet(backend)), backend


def test_registry_ignores_broken_files_and_stays_on_loopback(tmp_path):
    (tmp_path / "1234.json").write_text('{"port": 1234, "url": "http://evil.example/"}')
    (tmp_path / "bad.json").write_text("not json")
    (tmp_path / "x.json").write_text('{"pid": 3}')
    assert registered_urls(tmp_path) == ["http://127.0.0.1:1234/"]


def test_discover_lists_default_and_registered_windows(windows):
    first, second = windows
    live = InstanceSet(GhidraBackend(first.url)).discover()
    assert [d["url"] for d in live] == [first.url, second.url]
    assert [d["tool"] for d in live] == ["CodeBrowser", "CodeBrowser(2)"]
    assert live[1]["program"] == "OVERLAY_MENU"


def test_unreachable_registered_window_is_skipped(windows, tmp_path):
    first, _ = windows
    (tmp_path / "1.json").write_text('{"port": 1}')
    assert len(InstanceSet(GhidraBackend(first.url)).discover()) == 2


def test_resolve_by_port_name_and_errors(windows):
    first, second = windows
    instances = InstanceSet(GhidraBackend(first.url))
    port = str(second.server.server_address[1])
    assert instances.resolve(port) == second.url
    assert instances.resolve("overlay") == second.url
    assert instances.resolve("CodeBrowser(2)") == second.url
    with pytest.raises(BackendError, match="AMBIGUOUS_INSTANCE"):
        instances.resolve("codebrowser")
    with pytest.raises(BackendError, match="INSTANCE_NOT_FOUND"):
        instances.resolve("nothing")
    with pytest.raises(BackendError, match="INVALID_INSTANCE"):
        instances.resolve("http://example.com:8080/")


def test_instance_argument_routes_one_call(windows):
    first, second = windows
    mcp, _ = server_for(first)
    assert call(mcp, "get_program_info", instance="overlay") == {"name": "menu"}
    # The per-call target does not stick.
    assert call(mcp, "get_program_info") == {"name": "main"}


def test_every_backend_tool_accepts_instance(windows):
    first, _ = windows
    mcp, _ = server_for(first)
    tools = asyncio.run(mcp.list_tools())
    for t in tools:
        if t.name not in INSTANCE_TOOLS:
            assert "instance" in t.inputSchema["properties"], t.name
            assert "instance" not in t.inputSchema.get("required", []), t.name


def test_select_changes_default_and_list_marks_it(windows):
    first, second = windows
    mcp, backend = server_for(first)
    port = second.server.server_address[1]
    assert call(mcp, "select_ghidra_instance", instance=str(port))["program"] == "OVERLAY_MENU"
    assert backend.base_url == second.url
    assert call(mcp, "get_program_info") == {"name": "menu"}
    listing = call(mcp, "list_ghidra_instances")
    assert [d["selected"] for d in listing["instances"]] == [False, True]


def test_select_unknown_window_fails(windows):
    first, _ = windows
    mcp, backend = server_for(first)
    with pytest.raises(ToolError, match="INSTANCE_NOT_FOUND"):
        asyncio.run(mcp.call_tool("select_ghidra_instance", {"instance": "nothing"}))
    assert backend.base_url == first.url


def test_instance_tools_absent_without_instance_set():
    names = {t.name for t in asyncio.run(create_server(GhidraBackend(), capabilities=set()).list_tools())}
    assert not set(INSTANCE_TOOLS) & names

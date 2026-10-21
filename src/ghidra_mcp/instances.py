"""Discovery of the GhidraMCP backends running in open CodeBrowser windows.

Each window's plugin writes ``<port>.json`` to the instance directory (``$GHIDRA_MCP_INSTANCE_DIR``
or ``~/.ghidra_mcp/instances``) and removes it when the window closes. The first window keeps the
configured port (8080 by default); later windows take a free port.
"""

from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ghidra_mcp.backend import BackendError, GhidraBackend

INSTANCE_DIR_ENV = "GHIDRA_MCP_INSTANCE_DIR"
PROBE_TIMEOUT = 1.0
CACHE_SECONDS = 2.0


def instance_dir() -> Path:
    override = os.environ.get(INSTANCE_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / ".ghidra_mcp" / "instances"


def normalize(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def registered_urls(directory: Path | None = None) -> list[str]:
    """Backend URLs from the registry files. Only loopback URLs are accepted."""
    directory = directory or instance_dir()
    urls = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            port = int(entry["port"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        urls.append(f"http://127.0.0.1:{port}/")
    return urls


def describe(url: str, health: dict) -> dict[str, Any]:
    instance = health.get("instance") or {}
    program = health.get("program") or {}
    return {
        "port": urlparse(url).port,
        "url": url,
        "tool": instance.get("tool"),
        "project": instance.get("project"),
        "program": program.get("name"),
        "program_path": program.get("project_path"),
        "mode": health.get("mode"),
        "pid": instance.get("pid"),
    }


class InstanceSet:
    """Finds live backends and resolves an `instance` reference to a backend URL."""

    def __init__(self, backend: GhidraBackend, directory: Path | None = None):
        self.backend = backend
        self.directory = directory
        # The configured URL stays a candidate after select_ghidra_instance moves the default.
        self.configured_url = normalize(backend.base_url)
        self._lock = threading.Lock()
        self._cache: tuple[float, list[dict[str, Any]]] | None = None

    def candidate_urls(self) -> list[str]:
        urls = [self.configured_url]
        for url in [normalize(self.backend.base_url), *registered_urls(self.directory)]:
            if url not in urls:
                urls.append(url)
        return urls

    def discover(self, refresh: bool = False) -> list[dict[str, Any]]:
        """Live instances, the configured default first. Unreachable entries are skipped."""
        with self._lock:
            if not refresh and self._cache and time.monotonic() - self._cache[0] < CACHE_SECONDS:
                return self._cache[1]
        urls = self.candidate_urls()

        def probe(url: str) -> dict[str, Any] | None:
            health = GhidraBackend(url).health(PROBE_TIMEOUT)
            return describe(url, health) if health else None

        with ThreadPoolExecutor(max_workers=min(8, len(urls))) as pool:
            live = [d for d in pool.map(probe, urls) if d is not None]
        with self._lock:
            self._cache = (time.monotonic(), live)
        return live

    def resolve(self, ref: str) -> str:
        """Maps a port, URL, or case-insensitive substring of the tool/program/project to a URL."""
        ref = ref.strip()
        if ref.isdigit():
            return f"http://127.0.0.1:{int(ref)}/"
        if ref.startswith(("http://", "https://")):
            host = urlparse(ref).hostname
            if host not in ("127.0.0.1", "localhost", "::1"):
                raise BackendError("INVALID_INSTANCE", f"Only loopback backends are allowed: {ref}")
            return normalize(ref)
        needle = ref.lower()
        live = self.discover()
        matches = [
            d for d in live
            if any(needle in str(d.get(k) or "").lower()
                   for k in ("tool", "program", "program_path", "project"))
        ]
        if len(matches) == 1:
            return matches[0]["url"]
        known = ", ".join(f"{d['port']} ({d['tool']}: {d['program']})" for d in live) or "none"
        if not matches:
            raise BackendError("INSTANCE_NOT_FOUND", f"No open Ghidra window matches '{ref}'. Live: {known}")
        raise BackendError("AMBIGUOUS_INSTANCE", f"'{ref}' matches several windows; use a port. Live: {known}")

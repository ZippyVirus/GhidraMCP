"""Real Java HTTP regression: a queue of blocked normal calls must not starve control."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR")
JAR = Path(os.environ.get("GHIDRA_MCP_EXTENSION_JAR", ROOT / "extension/build/libs/GhidraMCP.jar"))


@pytest.mark.ghidra
@pytest.mark.skipif(not GHIDRA or not JAR.is_file(), reason="Ghidra and built extension required")
def test_project_job_reachable_with_more_blocked_requests_than_http_workers(tmp_path):
    java, javac = shutil.which("java"), shutil.which("javac")
    if not java or not javac:
        pytest.skip("Java compiler/runtime required")
    jars = [JAR, *Path(GHIDRA).joinpath("Ghidra").rglob("*.jar")]
    cp = os.pathsep.join(map(str, jars))
    source = ROOT / "tests/fixtures/ControlQueueSmoke.java"
    args = ["-encoding", "UTF-8", "-cp", cp, "-d", str(tmp_path), str(source)]
    response = tmp_path / "javac.args"
    response.write_text("\n".join('"' + a.replace("\\", "/") + '"' for a in args), encoding="utf-8")
    subprocess.run([javac, "@" + str(response)], check=True, capture_output=True, timeout=60)
    runtime = tmp_path / "java.args"
    runtime.write_text('"-cp"\n"' + (cp + os.pathsep + str(tmp_path)).replace("\\", "/")
                       + '"\nControlQueueSmoke\n', encoding="utf-8")
    process = subprocess.Popen([java, "@" + str(runtime)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        for _ in range(100):
            line = process.stdout.readline()
            if line.startswith("READY "):
                port = int(line.split()[1])
                break
            assert line, "Java fixture exited before opening its backend"
        else:
            pytest.fail("No backend startup marker")
        url = f"http://127.0.0.1:{port}"
        blocked = [pool.submit(requests.get, url + "/program_info", timeout=10) for _ in range(8)]
        time.sleep(0.2)
        # This would time out if queued normal calls occupied all HTTP workers.
        reply = requests.get(url + "/project_job", timeout=2)
        assert reply.status_code == 200
        assert reply.json()["data"]["state"] == "idle"
        process.stdin.write("x"); process.stdin.flush()
        assert all(f.result(timeout=5).status_code == 409 for f in blocked)
        process.stdin.write("q"); process.stdin.flush()
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
        pool.shutdown(wait=True, cancel_futures=True)

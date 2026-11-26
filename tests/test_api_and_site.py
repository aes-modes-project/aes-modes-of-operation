"""
Tests for the shared request handlers (aesmodes/api.py) and the web-version build
(tools/build_site.py). The handlers run both in the Flask server and in the browser
(Pyodide on GitHub Pages), so they must only need the standard library.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from aesmodes.api import ROUTES, handle

ROOT = Path(__file__).resolve().parent.parent
KEY = "2b7e151628aed2a6abf7158809cf4f3c"


def test_handle_matches_fips197():
    status, data = handle("POST", "/api/aes", {"key": KEY, "block": "3243f6a8885a308d313198a2e0370734"})
    assert status == 200 and data["ciphertext"] == "3925841d02dc09fbdc118597196a0b32"


def test_handle_errors_are_400_with_message():
    status, data = handle("POST", "/api/mode", {"mode": "ECB", "key": "abc", "data": "x"})
    assert status == 400 and "hex" in data["error"].lower()


def test_handle_wrong_key_padding_message():
    _, enc = handle("POST", "/api/mode", {"mode": "CBC", "operation": "encrypt", "key": KEY, "data": "hi"})
    status, data = handle("POST", "/api/mode", {"mode": "CBC", "operation": "decrypt",
                                                "key": "00" * 16, "data": enc["output"]})
    assert status == 400 and "wrong key" in data["error"]


def test_unknown_route_is_404():
    assert handle("GET", "/api/nothing")[0] == 404
    assert handle("GET", "/api/aes")[0] == 404           # wrong method


def test_every_route_answers():
    bodies = {
        "/api/aes": {"key": KEY, "block": "00" * 16},
        "/api/keys": {"key": KEY},
        "/api/mode": {"mode": "OFB", "key": KEY, "data": "x"},
        "/api/bitflip": {"key": KEY, "message": "hello world"},
        "/api/image": {"mode": "ECB", "key": KEY, "pixels": "AAAA"},
    }
    for method, path in ROUTES:
        assert handle(method, path, bodies.get(path, {}))[0] == 200, path


WEB_FILES = ["__init__.py", "aes_core.py", "padding.py", "modes.py", "explain.py", "api.py",
             "fastaes.py", "filecrypt.py"]


def test_browser_files_use_only_the_standard_library():
    """Pyodide has the standard library but not Flask/pycryptodome."""
    allowed = set(sys.stdlib_module_names) | {"aesmodes"}
    for f in WEB_FILES:
        tree = ast.parse((ROOT / "aesmodes" / f).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module]
            else:
                continue
            for n in names:
                assert n.split(".")[0] in allowed, f"{f} imports {n}"


def test_build_site(tmp_path):
    fake_pyodide = tmp_path / "pyodide"
    fake_pyodide.mkdir()
    for f in ["pyodide.js", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]:
        (fake_pyodide / f).write_text("x")
    out = tmp_path / "_site"
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_site.py"),
                    "--pyodide", str(fake_pyodide), "--out", str(out)], check=True, capture_output=True)
    assert (out / "index.html").exists() and (out / ".nojekyll").exists()
    assert (out / "static" / "js" / "common.js").exists()
    assert (out / "static" / "vendor" / "pyodide" / "pyodide.asm.wasm").exists()
    for f in WEB_FILES:
        assert (out / "py" / "aesmodes" / f).exists()
    for f in ["index.html", "app.js", "worker.js", "style.css"]:      # the AES Encryptor site
        assert (out / "encryptor" / f).exists()
    html = (out / "index.html").read_text()
    assert 'src="/static' not in html and 'href="/static' not in html   # relative paths only


def test_build_site_needs_pyodide(tmp_path):
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_site.py"),
                        "--pyodide", str(tmp_path / "missing"), "--out", str(tmp_path / "o")],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "Missing Pyodide file" in (r.stderr + r.stdout)


@pytest.mark.parametrize("path", ["js/common.js", "index.html"])
def test_app_files_exist(path):
    assert (ROOT / "aesmodes" / "web" / "static" / path).exists()

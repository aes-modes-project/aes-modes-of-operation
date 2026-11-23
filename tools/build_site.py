"""
build_site.py - build the web version of the learning app (for GitHub Pages).

    python tools/build_site.py --pyodide path/to/pyodide/package [--out _site]

The result is a folder of plain files that any static web host can serve:

    _site/
    ├── index.html                 the app (same page as the local version)
    ├── static/                    css, js, KaTeX
    │   └── vendor/pyodide/        Python compiled to WebAssembly (Pyodide)
    └── py/aesmodes/*.py           the project's own Python code, run by the browser

No server is needed: the page loads Pyodide and runs aesmodes/api.py in the
browser. The GitHub Actions workflow (.github/workflows/pages.yml) runs this
script on every push to main and publishes _site to GitHub Pages.

Pyodide is not stored in the repository (about 14 MB). The workflow downloads it
with `npm pack pyodide@<version>`; pass the extracted "package" folder here.
"""

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "aesmodes" / "web" / "static"
PY_FILES = ["__init__.py", "aes_core.py", "padding.py", "modes.py", "explain.py", "api.py"]
PYODIDE_FILES = ["pyodide.js", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip",
                 "pyodide-lock.json"]


def build(out: Path, pyodide: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(STATIC, out / "static")
    shutil.copy(STATIC / "index.html", out / "index.html")
    (out / "static" / "index.html").unlink()

    py_out = out / "py" / "aesmodes"
    py_out.mkdir(parents=True)
    for f in PY_FILES:
        shutil.copy(ROOT / "aesmodes" / f, py_out / f)

    vendor = out / "static" / "vendor" / "pyodide"
    vendor.mkdir(parents=True)
    for f in PYODIDE_FILES:
        src = pyodide / f
        if not src.exists():
            raise SystemExit(f"Missing Pyodide file: {src}")
        shutil.copy(src, vendor / f)

    (out / ".nojekyll").write_text("")      # serve files as they are (no Jekyll processing)
    total = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"Built {out} ({total / 1e6:.1f} MB)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pyodide", required=True, type=Path,
                    help="folder with pyodide.js, pyodide.asm.wasm, python_stdlib.zip, ...")
    ap.add_argument("--out", default=ROOT / "_site", type=Path)
    args = ap.parse_args()
    build(args.out, args.pyodide)


if __name__ == "__main__":
    main()

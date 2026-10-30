#!/usr/bin/env python3
"""Builds a clean, customer-ready release archive in dist/WebStrike-v<VERSION>.zip.

Automatically excludes:
  - .venv, __pycache__, .DS_Store, *.pyc
  - Local database & artifacts (scans/*.db*, scans/artifacts/*)
  - Developer-only files (tools/generate_license.py, apply_fixes.sh, selftest.log, Read this.txt, ROADMAP.md)
"""
from __future__ import annotations
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "1.1.0"
DIST_DIR = ROOT / "dist"

EXCLUDE_NAMES = {
    ".DS_Store",
    "apply_fixes.sh",
    "selftest.log",
    "Read this.txt",
    "ROADMAP.md",
    "generate_license.py",
}
EXCLUDE_DIRS = {".venv", "__pycache__", ".git", "dist", "artifacts"}


def should_include(rel: pathlib.Path) -> bool:
    for part in rel.parts:
        if part in EXCLUDE_DIRS or part.startswith("."):
            if part not in (".gitignore", ".github"):
                return False
    if rel.name in EXCLUDE_NAMES:
        return False
    if rel.suffix in {".pyc", ".pyo", ".db"} or ".db.bak" in rel.name or ".db-" in rel.name:
        return False
    return True


def build_release() -> pathlib.Path:
    import shutil
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_zip = DIST_DIR / f"WebStrike-v{VERSION}.zip"
    github_dir = ROOT.parent / "WebStrike-GitHub"
    if github_dir.exists():
        for child in github_dir.iterdir():
            if child.name == ".git":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        github_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(ROOT.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(ROOT)
            if not should_include(rel):
                continue
            arcname = str(pathlib.Path(f"WebStrike-v{VERSION}") / rel)
            zf.write(path, arcname)

            dest_file = github_dir / rel
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest_file)
            count += 1
        # Ensure empty scans/ directory placeholder exists in zip and GitHub folder
        zf.writestr(f"WebStrike-v{VERSION}/scans/.keep", "")
        keep_file = github_dir / "scans" / ".keep"
        keep_file.parent.mkdir(parents=True, exist_ok=True)
        keep_file.write_text("")
    print(f"[OK] Packaged {count} files -> {out_zip} ({out_zip.stat().st_size:,} bytes)")
    print(f"[OK] Prepared clean GitHub repository folder -> {github_dir}")
    return out_zip


if __name__ == "__main__":
    build_release()

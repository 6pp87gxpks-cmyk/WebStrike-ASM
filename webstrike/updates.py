"""Update checker: compares the running version with the published latest release."""
from __future__ import annotations
import asyncio
import os
from pathlib import Path
import time
from typing import Dict, Optional, Tuple

from . import __version__, UPDATE_URL

_CACHE: Dict = {"ts": 0.0, "data": None}
CACHE_SECONDS = 6 * 3600
REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_version(v: str) -> Tuple[int, ...]:
    parts = []
    for p in str(v).strip().lstrip("vV").split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer(latest: str, current: str) -> bool:
    return parse_version(latest) > parse_version(current)


async def check_for_update(force: bool = False) -> Dict:
    url = os.environ.get("WEBSTRIKE_UPDATE_URL", UPDATE_URL).strip()
    result: Dict = {"current": __version__, "latest": None, "update_available": False,
                    "notes": None, "download": None, "enabled": bool(url)}
    if not url:
        return result
    now = time.time()
    if not force and _CACHE["data"] and now - _CACHE["ts"] < CACHE_SECONDS:
        return _CACHE["data"]
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as c:
            r = await c.get(url, headers={"Accept": "application/json"})
            r.raise_for_status()
            info = r.json()
        # Support both custom version.json AND GitHub Releases API (/repos/<owner>/<repo>/releases/latest)
        raw_ver = info.get("version") or info.get("tag_name") or ""
        latest: Optional[str] = str(raw_ver).lstrip("vV") or None
        notes = info.get("notes") or info.get("body")
        download = info.get("download") or info.get("html_url")
        result.update(latest=latest, notes=notes, download=download,
                      update_available=bool(latest and is_newer(latest, __version__)))
    except Exception as e:  # offline / bad URL: never break the app
        result["error"] = type(e).__name__
    _CACHE.update(ts=now, data=result)
    return result


async def apply_git_update(repo_dir: Path = REPO_ROOT) -> Dict:
    """Pulls the latest commits via `git pull --ff-only` when installed from a GitHub clone."""
    git_dir = repo_dir / ".git"
    if not git_dir.exists():
        return {
            "ok": False,
            "message": "This folder is not a Git repository yet (no .git folder). Clone from GitHub or download the latest release ZIP.",
        }
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "pull", "--ff-only",
            cwd=str(repo_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        out = (stdout_b.decode(errors="replace") + "\n" + stderr_b.decode(errors="replace")).strip()
        _CACHE.update(ts=0.0, data=None)
        if proc.returncode == 0:
            return {"ok": True, "message": out or "Already up to date."}
        return {"ok": False, "message": out or f"git pull exited with code {proc.returncode}"}
    except Exception as e:
        return {"ok": False, "message": f"Git update failed: {e}"}

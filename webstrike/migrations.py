"""Versioned database migrations.

Each migration runs exactly once, in order. The current schema version is stored
in SQLite's built-in ``PRAGMA user_version``. Before any migration is applied to an
existing database, a backup copy of the database file is written next to it, so a
customer's data can always be restored if an update goes wrong.

RULES for adding a migration (future updates):
  * Append a new entry to MIGRATIONS with the next version number.
  * Never edit or reorder an existing migration once it has been released.
  * Prefer additive changes (new tables / new columns with defaults).
"""
from __future__ import annotations
import shutil
import time
from pathlib import Path
from typing import Callable, List, Tuple, Union

Step = Union[str, Callable]

# Version 1 is the original WebStrike schema. All statements are idempotent so that
# databases created before the migration system existed are adopted safely.
_V1_BASE = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, target TEXT, profile TEXT, status TEXT,
    started REAL, finished REAL, stats TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    fp TEXT, scan_id TEXT, module TEXT, title TEXT, severity TEXT,
    confidence TEXT, category TEXT, target TEXT, url TEXT,
    evidence TEXT, meta TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, username TEXT, expires_at REAL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
"""

# Version 2: generic key/value settings (scope allowlist, instance options, ...).
_V2_SETTINGS = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT, updated_at REAL
);
"""

MIGRATIONS: List[Tuple[int, str, Step]] = [
    (1, "base schema", _V1_BASE),
    (2, "settings table", _V2_SETTINGS),
]

LATEST_VERSION = MIGRATIONS[-1][0]


async def get_version(db) -> int:
    cur = await db.execute("PRAGMA user_version")
    row = await cur.fetchone()
    return int(row[0]) if row else 0


async def _has_tables(db) -> bool:
    cur = await db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
    row = await cur.fetchone()
    return bool(row and row[0])


def backup_db(db_path: Path, from_version: int) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = db_path.with_name(f"{db_path.name}.bak-v{from_version}-{stamp}")
    shutil.copy2(db_path, dest)
    return dest


async def migrate(db, db_path: Path) -> List[str]:
    """Bring the database up to LATEST_VERSION. Returns a log of applied steps."""
    applied: List[str] = []
    current = await get_version(db)
    if current > LATEST_VERSION:
        raise RuntimeError(
            f"Database schema v{current} is newer than this WebStrike build "
            f"(supports up to v{LATEST_VERSION}). Please update WebStrike.")
    pending = [m for m in MIGRATIONS if m[0] > current]
    if not pending:
        return applied

    if db_path.exists() and await _has_tables(db):
        dest = backup_db(db_path, current)
        applied.append(f"backup -> {dest.name}")

    for version, desc, step in pending:
        try:
            if callable(step):
                await step(db)
            else:
                await db.executescript(step)
            await db.execute(f"PRAGMA user_version = {int(version)}")
            await db.commit()
            applied.append(f"v{version}: {desc}")
        except Exception:
            await db.rollback()
            raise
    return applied

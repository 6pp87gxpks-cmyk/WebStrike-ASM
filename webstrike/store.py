from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

import aiosqlite

from .migrations import migrate

DATA_DIR = Path(
    os.environ.get("WEBSTRIKE_DATA_DIR")
    or (Path(__file__).resolve().parent.parent / "scans")
).resolve()
DB_PATH = DATA_DIR / "webstrike.db"


def fingerprint(f) -> str:
    raw = f"{f.module}|{f.title}|{f.url or f.target}|{(f.evidence or '')[:200]}"
    return hashlib.sha1(raw.encode()).hexdigest()


class Store:
    def __init__(self, path: Path = DB_PATH):
        self.path = Path(path)
        self._db = None
        self._lock = asyncio.Lock()

    async def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        self.migration_log = await migrate(self._db, self.path)
        return self

    async def close(self):
        if self._db:
            await self._db.close()

    async def get_setting(self, key: str, default=None):
        if not self._db:
            return default
        cur = await self._db.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cur.fetchone()
        if not row:
            return default
        try:
            return json.loads(row[0])
        except Exception:
            return default

    async def set_setting(self, key: str, value) -> None:
        if not self._db:
            return
        async with self._lock:
            await self._db.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, json.dumps(value), time.time()),
            )
            await self._db.commit()

    async def delete_scan(self, scan_id: str) -> bool:
        if not self._db:
            return False
        async with self._lock:
            try:
                await self._db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                await self._db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                await self._db.commit()
                return True
            except Exception:
                return False

    async def save_scan(self, engine):
        if not self._db:
            return
        async with self._lock:
            await self._db.execute(
                "INSERT OR REPLACE INTO scans(id,target,profile,status,started,finished,stats)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    engine.scan_id,
                    engine.target,
                    engine.opt.profile,
                    engine.status,
                    engine.started,
                    time.time(),
                    json.dumps(engine.surface_stats()),
                ),
            )
            await self._db.execute("DELETE FROM findings WHERE scan_id=?", (engine.scan_id,))
            rows = [
                (
                    fingerprint(f),
                    engine.scan_id,
                    f.module,
                    f.title,
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    f.category,
                    f.target,
                    f.url,
                    (f.evidence or "")[:1000],
                    json.dumps(f.meta, default=str),
                    f.ts,
                )
                for f in engine.findings
            ]
            await self._db.executemany(
                "INSERT INTO findings(fp,scan_id,module,title,severity,confidence,category,"
                "target,url,evidence,meta,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            await self._db.commit()

    async def list_scans(self, limit=100):
        if not self._db:
            return []
        cur = await self._db.execute(
            "SELECT s.id,s.target,s.profile,s.status,s.started,s.finished,s.stats,"
            " (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS n "
            "FROM scans s ORDER BY s.started DESC LIMIT ?",
            (limit,),
        )
        rows = await cur.fetchall()
        return [
            {
                "id": r[0],
                "target": r[1],
                "profile": r[2],
                "status": r[3],
                "started": r[4],
                "finished": r[5],
                "stats": json.loads(r[6] or "{}"),
                "findings": r[7],
            }
            for r in rows
        ]

    async def previous_scan(self, target, exclude_id):
        if not self._db:
            return None
        cur = await self._db.execute(
            "SELECT id FROM scans WHERE target=? AND id<>? AND status='done'"
            " ORDER BY started DESC LIMIT 1",
            (target, exclude_id),
        )
        row = await cur.fetchone()
        return row[0] if row else None

    async def load_fingerprints(self, scan_id):
        if not self._db:
            return set()
        cur = await self._db.execute("SELECT fp FROM findings WHERE scan_id=?", (scan_id,))
        return {r[0] for r in await cur.fetchall()}

    async def load_findings(self, scan_id):
        if not self._db:
            return []
        cur = await self._db.execute(
            "SELECT module,title,severity,confidence,category,target,url,evidence,meta,ts,fp"
            " FROM findings WHERE scan_id=?",
            (scan_id,),
        )
        rows = await cur.fetchall()
        return [
            {
                "module": r[0],
                "title": r[1],
                "severity": r[2],
                "confidence": r[3],
                "category": r[4],
                "target": r[5],
                "url": r[6],
                "evidence": r[7],
                "meta": json.loads(r[8] or "{}"),
                "ts": r[9],
                "fp": r[10],
            }
            for r in rows
        ]

    async def restore_backup(self, payload: dict) -> dict:
        if not self._db or not isinstance(payload, dict):
            return {"scans_restored": 0, "findings_restored": 0}
        scope = payload.get("scope")
        if isinstance(scope, dict):
            raw_domains = scope.get("domains")
            domains_list = [str(d) for d in raw_domains] if isinstance(raw_domains, list) else []
            await self.set_setting(
                "scope",
                {
                    "enforce": bool(scope.get("enforce", False)),
                    "domains": domains_list,
                },
            )

        def _safe_float(val, default: float) -> float:
            try:
                return float(val) if val is not None else default
            except (TypeError, ValueError):
                return default

        raw_scans = payload.get("scans")
        scans = raw_scans if isinstance(raw_scans, list) else []
        raw_fmap = payload.get("findings")
        findings_map = raw_fmap if isinstance(raw_fmap, dict) else {}
        scans_restored = 0
        findings_restored = 0

        async with self._lock:
            for sc in scans:
                if not isinstance(sc, dict) or not sc.get("id") or not sc.get("target"):
                    continue
                sid = str(sc["id"])
                raw_stats = sc.get("stats")
                stats_dict = raw_stats if isinstance(raw_stats, dict) else {}
                now = time.time()
                await self._db.execute(
                    "INSERT OR REPLACE INTO scans(id,target,profile,status,started,finished,stats)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (
                        sid,
                        str(sc.get("target", "")),
                        str(sc.get("profile", "balanced")),
                        str(sc.get("status", "done")),
                        _safe_float(sc.get("started"), now),
                        _safe_float(sc.get("finished"), now),
                        json.dumps(stats_dict),
                    ),
                )
                scans_restored += 1
                f_list = findings_map.get(sid)
                if not isinstance(f_list, list) and isinstance(sc.get("findings"), list):
                    f_list = sc.get("findings")
                if isinstance(f_list, list):
                    await self._db.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
                    rows = []
                    for f in f_list:
                        if not isinstance(f, dict):
                            continue
                        mod = str(f.get("module", "unknown"))
                        title = str(f.get("title", "Finding"))
                        target_val = str(f.get("target") or "")
                        url_val = str(f.get("url") or "")
                        ev_val = str(f.get("evidence") or "")[:1000]
                        default_fp = hashlib.sha1(
                            f"{mod}|{title}|{url_val or target_val}|{ev_val[:200]}".encode()
                        ).hexdigest()
                        fp_val = str(f.get("fp") or default_fp)
                        raw_meta = f.get("meta")
                        meta_dict = raw_meta if isinstance(raw_meta, dict) else {}
                        rows.append(
                            (
                                fp_val,
                                sid,
                                mod,
                                title,
                                str(f.get("severity", "info")),
                                str(f.get("confidence", "firm")),
                                str(f.get("category", "general")),
                                target_val,
                                url_val,
                                ev_val,
                                json.dumps(meta_dict, default=str),
                                _safe_float(f.get("ts"), now),
                            )
                        )
                    if rows:
                        await self._db.executemany(
                            "INSERT INTO findings(fp,scan_id,module,title,severity,confidence,category,"
                            "target,url,evidence,meta,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            rows,
                        )
                        findings_restored += len(rows)

            await self._db.commit()
        return {"scans_restored": scans_restored, "findings_restored": findings_restored}

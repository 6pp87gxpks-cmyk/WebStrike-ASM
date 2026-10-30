from __future__ import annotations
import asyncio, json, pathlib, shutil, time, uuid
from contextlib import asynccontextmanager
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import Options
from ..engine import Engine
from ..store import Store, DATA_DIR
from ..remediation import get_remediation
from ..report import generate_executive_report_html
from ..scope import DEFAULT_SCOPE, target_host, normalize_list, host_in_scope
from ..updates import check_for_update, apply_git_update
from ..migrations import LATEST_VERSION

STATIC = pathlib.Path(__file__).parent / "static"
store: Optional[Store] = None

@asynccontextmanager
async def lifespan(app):
    global store
    store = await Store().connect()
    yield
    if store:
        await store.close()

app = FastAPI(title="WebStrike", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
SCANS: dict[str, dict] = {}

class ScopeReq(BaseModel):
    enforce: bool = False
    domains: List[str] = []

class ScanReq(BaseModel):
    target: str
    profile: str = "balanced"
    only_modules: Optional[List[str]] = None
    cookies: Optional[Dict] = None
    headers: Optional[Dict] = None
    bearer: Optional[str] = None
    basic: Optional[str] = None
    proxy: Optional[str] = None
    webhook: Optional[str] = None
    concurrency: int = 30
    rate: float = 0.0
    authorized: bool = True

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(
        content=(STATIC / "index.html").read_text(),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
    )

@app.get("/api/version")
async def version_api(refresh: bool = False):
    info = await check_for_update(force=refresh)
    info["schema_version"] = LATEST_VERSION
    return info

@app.get("/api/scope")
async def get_scope():
    if not store:
        return DEFAULT_SCOPE
    return await store.get_setting("scope", DEFAULT_SCOPE)

@app.post("/api/scope")
async def save_scope(req: ScopeReq):
    if not store:
        raise HTTPException(status_code=500, detail="Database not ready")
    cleaned = {"enforce": bool(req.enforce), "domains": normalize_list(req.domains)}
    await store.set_setting("scope", cleaned)
    return cleaned

@app.get("/api/modules")
async def modules():
    from ..registry import MODULES
    return [{"id": m.id, "name": m.name, "phase": m.phase.value, "profiles": list(m.profiles)}
            for m in sorted(MODULES.values(), key=lambda x: (x.phase.value, x.id))]

@app.get("/api/history")
async def history():
    if not store:
        return []
    return await store.list_scans()

@app.get("/api/scan/{sid}/findings")
async def scan_findings(sid: str):
    return await _load_scan_findings(sid)

async def _load_scan_findings(sid: str):
    s = SCANS.get(sid)
    if s:
        e = s["engine"]
        if e.findings:
            return [f.to_dict() if hasattr(f, "to_dict") else f for f in e.findings]
    if store:
        return await store.load_findings(sid)
    return []

@app.post("/api/scan")
async def start_scan(req: ScanReq):
    if not req.authorized:
        raise HTTPException(status_code=400, detail="You must confirm authorization to scan this target")
    t = req.target.strip()
    if not t:
        raise HTTPException(status_code=400, detail="Target is required")
    if store:
        scope = await store.get_setting("scope", DEFAULT_SCOPE)
        if scope and scope.get("enforce"):
            host = target_host(t)
            if not host_in_scope(host, scope.get("domains") or []):
                raise HTTPException(
                    status_code=403,
                    detail=f"Target '{host or t}' is outside the allowed scope. Add it in Scope Settings first."
                )
    sid = uuid.uuid4().hex[:8]
    kind = Engine.detect_kind(t)
    opt = Options(profile=req.profile, only_modules=req.only_modules,
                  cookies=req.cookies or {}, headers=req.headers or {},
                  bearer=req.bearer, basic=req.basic, proxy=req.proxy,
                  webhook_url=req.webhook,
                  concurrency=req.concurrency, rate=req.rate)
    eng = Engine(sid, t, kind, opt, store=store)
    task = asyncio.create_task(eng.run())
    SCANS[sid] = {"engine": eng, "task": task}
    return {"id": sid}

@app.get("/api/scan/{sid}/compare/{other_sid}")
async def compare_scans(sid: str, other_sid: str):
    if not store:
        raise HTTPException(status_code=500, detail="Database not ready")
    f_curr = await _load_scan_findings(sid)
    f_prev = await _load_scan_findings(other_sid)

    def _sig(item: Dict) -> str:
        return f"{item.get('module')}|{item.get('title')}|{item.get('url') or item.get('target')}"

    curr_map = {_sig(f): f for f in f_curr}
    prev_map = {_sig(f): f for f in f_prev}

    new_items = [f for k, f in curr_map.items() if k not in prev_map]
    resolved_items = [f for k, f in prev_map.items() if k not in curr_map]
    unchanged_items = [f for k, f in curr_map.items() if k in prev_map]

    return {
        "scan_id": sid,
        "baseline_id": other_sid,
        "counts": {
            "new": len(new_items),
            "resolved": len(resolved_items),
            "unchanged": len(unchanged_items),
        },
        "new": new_items,
        "resolved": resolved_items,
        "unchanged": unchanged_items,
    }

@app.get("/api/backup")
async def export_backup():
    if not store:
        raise HTTPException(status_code=500, detail="Database not ready")
    scans = await store.list_scans(limit=1000)
    all_findings = {}
    for sc in scans:
        all_findings[sc["id"]] = await store.load_findings(sc["id"])
    scope = await store.get_setting("scope", DEFAULT_SCOPE)
    payload = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "schema_version": LATEST_VERSION,
        "scope": scope,
        "scans": scans,
        "findings": all_findings,
    }
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="webstrike-backup-{int(time.time())}.json"'}
    )

@app.post("/api/backup/restore")
async def restore_backup(payload: Dict):
    if not store:
        raise HTTPException(status_code=500, detail="Database not ready")
    if not isinstance(payload, dict) or ("scans" not in payload and "scope" not in payload):
        raise HTTPException(status_code=400, detail="Invalid backup JSON format")
    res = await store.restore_backup(payload)
    return {"status": "restored", **res}

@app.post("/api/update/pull")
async def pull_update():
    return await apply_git_update()

@app.post("/api/scan/{sid}/stop")
async def stop_scan(sid: str):
    s = SCANS.get(sid)
    if not s:
        raise HTTPException(status_code=404, detail="Active scan not found")
    task = s.get("task")
    eng = s["engine"]
    if task and not task.done():
        task.cancel()
    eng.status = "stopped"
    return {"status": "stopped", "id": sid}

@app.delete("/api/scan/{sid}")
async def delete_scan(sid: str):
    if not store:
        raise HTTPException(status_code=500, detail="Database not ready")
    if sid in SCANS:
        s = SCANS[sid]
        task = s.get("task")
        if task and not task.done():
            task.cancel()
        del SCANS[sid]
    scan_art_dir = DATA_DIR / "artifacts" / sid
    if scan_art_dir.exists() and scan_art_dir.is_dir():
        shutil.rmtree(scan_art_dir, ignore_errors=True)
    ok = await store.delete_scan(sid)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found or failed to delete")
    return {"status": "deleted", "id": sid}

@app.get("/api/scan/{sid}")
async def get_scan(sid: str):
    s = SCANS.get(sid)
    if s:
        e = s["engine"]
        return {"id": sid, "status": e.status, "target": e.target, "profile": e.opt.profile,
                "findings": [{**f.to_dict()} for f in e.findings], "surface": e.surface_stats()}
    if store:
        scans = await store.list_scans()
        scan = next((s for s in scans if s["id"] == sid), None)
        if scan:
            findings = await store.load_findings(sid)
            return {"id": sid, "status": scan["status"], "target": scan["target"],
                    "profile": scan["profile"], "findings": findings, "surface": scan["stats"]}
    return JSONResponse({"error": "not found"}, 404)

@app.get("/api/scan/{sid}/report", response_class=HTMLResponse)
async def scan_report(sid: str):
    target = sid
    profile = "balanced"
    findings = []
    surface = {}
    elapsed = 0.0
    started = 0.0

    s = SCANS.get(sid)
    if s:
        e = s["engine"]
        target = e.target
        profile = e.opt.profile
        findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in e.findings]
        surface = e.surface_stats()
        elapsed = round(time.time() - e.started, 1)
        started = e.started
    elif store:
        findings = await store.load_findings(sid)
        scans = await store.list_scans()
        scan = next((sc for sc in scans if sc["id"] == sid), None)
        if not scan and not findings:
            return HTMLResponse(content="<h1>404 — Scan not found</h1>", status_code=404)
        if scan:
            target = scan.get("target", sid)
            profile = scan.get("profile", "balanced")
            surface = scan.get("stats", {})
            started = scan.get("started", 0.0)
            elapsed = round(scan.get("finished", 0.0) - started, 1) if scan.get("finished") else 0.0
    else:
        return HTMLResponse(content="<h1>404 — Scan not found</h1>", status_code=404)

    report_html = generate_executive_report_html(
        target=target,
        profile=profile,
        findings=findings,
        surface=surface,
        elapsed=elapsed,
        scan_id=sid,
        started_ts=started
    )
    return HTMLResponse(content=report_html)

@app.get("/scans/{sid}/screens/{name}")
async def screen(sid: str, name: str):
    base_dir = (DATA_DIR / "artifacts" / sid / "screens").resolve()
    p = (base_dir / name).resolve()
    if not str(p).startswith(str(base_dir)) or not p.is_file():
        return JSONResponse({"error": "not found"}, 404)
    return FileResponse(p)

@app.get("/api/scan/{sid}/export")
async def export(sid: str, fmt: str = "json"):
    target = sid
    findings = []
    s = SCANS.get(sid)
    if s:
        e = s["engine"]
        target = e.target
        findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in e.findings]
    elif store:
        findings = await store.load_findings(sid)
        scans = await store.list_scans()
        target = next((sc["target"] for sc in scans if sc["id"] == sid), sid)
        if not findings and not any(sc["id"] == sid for sc in scans):
            return JSONResponse({"error": "not found"}, 404)
    else:
        return JSONResponse({"error": "not found"}, 404)

    SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if fmt == "md":
        lines = [f"# WebStrike Security Report — {target}\n"]
        for f in sorted(findings, key=lambda x: SEV_RANK.get(str(x.get("severity", "")).lower(), 9)):
            sev = str(f.get("severity", "info")).upper()
            title = f.get("title", "")
            cat = f.get("category", "")
            loc = f.get("url") or f.get("target", "")
            ev = str(f.get("evidence", ""))[:140]
            rem = get_remediation(cat, title)
            lines.append(f"- **[{sev}]** {title} — `{loc}`\n  - *Evidence:* `{ev}`\n  - *Remediation:* {rem}\n")
        return PlainTextResponse("\n".join(lines))
    return JSONResponse(findings)

@app.websocket("/ws/{sid}")
async def ws(ws: WebSocket, sid: str):
    await ws.accept()
    s = SCANS.get(sid)
    if not s:
        await ws.close()
        return
    eng = s["engine"]
    q = eng.subscribe()
    try:
        for ev in list(eng.history):
            await ws.send_text(json.dumps(ev))
        if any(ev.get("kind") == "scan_done" for ev in eng.history) or eng.status in ("done", "stopped"):
            return
        while True:
            ev = await q.get()
            await ws.send_text(json.dumps(ev))
            if ev.get("kind") == "scan_done":
                break
    except WebSocketDisconnect:
        pass
    finally:
        eng.unsubscribe(q)

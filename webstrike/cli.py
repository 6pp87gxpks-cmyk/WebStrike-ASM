import asyncio
import uuid

from rich.console import Console
from rich.markup import escape

from .config import Options
from .engine import Engine
from .store import Store

console = Console()
COLOR = {
    "critical": "red",
    "high": "orange3",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}


def run_cli(target, profile, only=None):
    sid = uuid.uuid4().hex[:8]

    async def main():
        store = await Store().connect()
        eng = Engine(
            sid,
            target,
            Engine.detect_kind(target),
            Options(profile=profile, only_modules=only),
            store=store,
        )
        q = eng.subscribe()
        task = asyncio.create_task(eng.run())
        try:
            while True:
                if task.done() and q.empty():
                    if task.exception():
                        console.print(f"[red]Scan engine error: {escape(str(task.exception()))}[/]")
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    if task.done():
                        if task.exception():
                            console.print(f"[red]Scan engine error: {escape(str(task.exception()))}[/]")
                        break
                    continue

                kind = ev.get("kind")
                if kind == "finding":
                    f = ev["finding"]
                    sev = str(f.get("severity", "info"))
                    color = COLOR.get(sev, "white")
                    loc = escape(str(f.get("url") or f.get("target") or ""))
                    console.print(f"[{color}]{escape(sev.upper())}[/] {escape(str(f.get('title', '')))} [dim]{loc}[/]")
                elif kind == "module_error":
                    console.print(f"[red]x {escape(str(ev.get('module', '')))}[/]: {escape(str(ev.get('error', '')))}")
                elif kind == "module_start":
                    console.print(f"[dim]> {escape(str(ev.get('name', '')))}[/]")
                elif kind == "scan_diff" and ev.get("new"):
                    console.print(
                        f"[bold yellow]delta {ev['new']} new vs {escape(str(ev['prev']))}, "
                        f"{ev['resolved']} resolved[/]"
                    )
                elif kind == "log":
                    console.print(f"[dim]{escape(str(ev.get('message', '')))}[/]")
                elif kind == "scan_done":
                    console.print(f"\n[bold green]done[/] {ev['total']} findings in {ev['elapsed']}s")
                    break
        finally:
            if not task.done():
                await task
            await store.close()

    asyncio.run(main())

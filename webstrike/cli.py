import asyncio, uuid
from rich.console import Console
from .config import Options
from .engine import Engine
from .store import Store

console = Console()
COLOR = {"critical": "red", "high": "orange3", "medium": "yellow",
         "low": "green", "info": "dim"}

def run_cli(target, profile, only=None):
    sid = uuid.uuid4().hex[:8]

    async def main():
        store = await Store().connect()
        eng = Engine(sid, target, Engine.detect_kind(target),
                     Options(profile=profile, only_modules=only), store=store)
        q = eng.subscribe()
        task = asyncio.create_task(eng.run())
        try:
            while True:
                if task.done() and q.empty():
                    if task.exception():
                        console.print(f"[red]Scan engine error: {task.exception()}[/]")
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    if task.done():
                        if task.exception():
                            console.print(f"[red]Scan engine error: {task.exception()}[/]")
                        break
                    continue

                k = ev.get("kind")
                if k == "finding":
                    f = ev["finding"]
                    sev = f["severity"]
                    console.print("[" + COLOR.get(sev, "white") + "]" + sev.upper() +
                                  "[/] " + f["title"] + " [dim]" +
                                  (f["url"] or f["target"]) + "[/]")
                elif k == "module_error":
                    console.print("[red]x " + ev["module"] + "[/]: " + ev["error"])
                elif k == "module_start":
                    console.print("[dim]> " + ev["name"] + "[/]")
                elif k == "scan_diff" and ev.get("new"):
                    console.print("[bold yellow]delta " + str(ev["new"]) + " new vs " +
                                  str(ev["prev"]) + ", " + str(ev["resolved"]) + " resolved[/]")
                elif k == "log":
                    console.print("[dim]" + ev["message"] + "[/]")
                elif k == "scan_done":
                    console.print("\n[bold green]done[/] " + str(ev["total"]) +
                                  " findings in " + str(ev["elapsed"]) + "s")
                    break
        finally:
            if not task.done():
                await task
            await store.close()

    asyncio.run(main())

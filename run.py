#!/usr/bin/env python3
import argparse, sys

def main():
    p = argparse.ArgumentParser(prog="webstrike")
    sub = p.add_subparsers(dest="cmd")
    web = sub.add_parser("web"); web.add_argument("--host", default="127.0.0.1"); web.add_argument("--port", type=int, default=8777)
    web.add_argument("--dev", action="store_true", help="auto-reload on code changes (development only)")
    sc = sub.add_parser("scan"); sc.add_argument("target"); sc.add_argument("-p","--profile", default="balanced", choices=["passive","balanced","danger"])
    sc.add_argument("-m","--modules"); 
    a = p.parse_args()
    if a.cmd == "scan":
        from webstrike.cli import run_cli
        run_cli(a.target, a.profile, a.modules.split(",") if a.modules else None)
    else:
        import uvicorn
        host = getattr(a, "host", "127.0.0.1"); port = getattr(a, "port", 8777)
        print(f"WebStrike dashboard → http://{host}:{port}")
        uvicorn.run("webstrike.server.app:app", host=host, port=port,
                    reload=getattr(a, "dev", False), log_level="warning")

if __name__ == "__main__":
    sys.exit(main())

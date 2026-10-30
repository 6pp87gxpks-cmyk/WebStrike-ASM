#!/usr/bin/env python3
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(prog="webstrike")
    sub = parser.add_subparsers(dest="cmd")

    web = sub.add_parser("web")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8777)
    web.add_argument("--dev", action="store_true", help="auto-reload on code changes")

    sc = sub.add_parser("scan")
    sc.add_argument("target")
    sc.add_argument("-p", "--profile", default="balanced", choices=["passive", "balanced", "danger"])
    sc.add_argument("-m", "--modules")

    args = parser.parse_args()
    if args.cmd == "scan":
        from webstrike.cli import run_cli
        mods = [m.strip() for m in args.modules.split(",") if m.strip()] if args.modules else None
        run_cli(args.target, args.profile, mods or None)
    else:
        import uvicorn
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8777)
        print(f"WebStrike dashboard -> http://{host}:{port}")
        uvicorn.run(
            "webstrike.server.app:app",
            host=host,
            port=port,
            reload=getattr(args, "dev", False),
            log_level="warning",
        )


if __name__ == "__main__":
    sys.exit(main())

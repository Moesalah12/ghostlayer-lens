"""python -m lens scan FILE | python -m lens serve"""
import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .engine import Limits
from .worker import isolated_scan


def main(argv=None):
    parser = argparse.ArgumentParser(description="GhostLayer Lens — understand a download before you open it.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="inspect one local file without executing it")
    scan.add_argument("file", type=Path)
    scan.add_argument("--output", type=Path, help="create a JSON report; refuses to overwrite")
    serve = sub.add_parser("serve", help="start the local-only visual app")
    serve.add_argument("--port", type=int, default=0, help="default: random available port")
    serve.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "serve":
        from .server import serve_app
        return serve_app(args.port, not args.no_browser)
    try:
        if args.file.is_symlink() or not args.file.is_file():
            raise ValueError("Choose a regular file, not a directory or symbolic link.")
        with args.file.open("rb") as stream:
            data = stream.read(Limits().input_bytes+1)
        if len(data) > Limits().input_bytes:
            raise ValueError("Input exceeds the 20 MiB limit.")
        report = isolated_scan(data, args.file.name)
        encoded = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        else:
            print(encoded, end="")
        return 1 if report["assessment"] == "review_recommended" or report["coverage"] == "incomplete" else 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"lens: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

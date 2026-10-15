"""Run untrusted parsers in a disposable, time-bounded subprocess.

This is process separation, NOT an OS security sandbox. Linux adds resource
limits where available. No file is executed as a program.
"""
import json
from pathlib import Path
import subprocess
import sys


def isolated_scan(data, name):
    root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run([sys.executable, "-m", "lens.worker", name], input=data,
                                capture_output=True, timeout=15, cwd=root)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Inspection exceeded 15 seconds; no complete report was produced.") from exc
    if result.returncode != 0:
        raise RuntimeError("Inspection process stopped without a complete report; content remains unassessed.")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Inspection process returned an invalid report.") from exc


def main():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (384*1024*1024, 384*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
    except (ImportError, ValueError, OSError):
        pass
    from .engine import Limits, scan_bytes
    data = sys.stdin.buffer.read(Limits().input_bytes+1)
    try:
        report = scan_bytes(data, sys.argv[1])
        sys.stdout.write(json.dumps(report, ensure_ascii=True))
        return 0
    except (ValueError, MemoryError, RecursionError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

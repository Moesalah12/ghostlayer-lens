"""Run untrusted parsers in a disposable, time-bounded subprocess.

This is process separation, NOT an OS security sandbox. Linux adds resource
limits where available. No file is executed as a program.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def isolated_scan(data, name):
    with tempfile.TemporaryDirectory(prefix="ghostlayer-lens-") as directory:
        path = Path(directory) / "input"
        path.write_bytes(data)
        return isolated_scan_file(path, name)


def isolated_scan_file(path, name):
    root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run([sys.executable, "-m", "lens.worker", name, str(Path(path).resolve())],
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
    from .engine import scan_file
    try:
        report = scan_file(sys.argv[2], sys.argv[1])
        sys.stdout.write(json.dumps(report, ensure_ascii=True))
        return 0
    except (OSError, ValueError, MemoryError, RecursionError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

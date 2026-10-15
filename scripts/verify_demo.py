"""Verify the generated training ZIP using the actual CLI and schema."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
file = sys.argv[1] if len(sys.argv) > 1 else "examples/training.zip"
result = subprocess.run([sys.executable, "-m", "lens", "scan", file], cwd=root, capture_output=True, text=True, timeout=20)
if result.returncode != 1:
    raise SystemExit(f"Expected review exit 1, got {result.returncode}: {result.stderr}")
report = json.loads(result.stdout)
expected = {"remote_retrieval", "elevation_request", "disguised_extension", "binary_not_analyzed"}
actual = {item["rule"] for item in report["findings"]}
if not expected.issubset(actual) or report["stats"]["nodes"] != 5 or report["coverage"] != "incomplete":
    raise SystemExit("Training report did not match expected evidence.")
print("Training ZIP verified: 5 nodes, expected evidence, incomplete binary coverage, exit 1.")

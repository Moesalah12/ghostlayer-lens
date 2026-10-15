# Validation record

Local environment: Linux, Python 3.12.14. Initial validation: 2026-10-15 UTC.

- 40 Python tests passed across engine, CLI, and local server, including symlinks disguised as directory entries.
- JavaScript syntax check passed.
- The actual browser ZIP builder passed a known CRC32 vector and four-entry inventory check under Node.
- Its generated ZIP was scanned through the real CLI and produced the expected review findings and incomplete-binary coverage.
- The Python training generator also passed the real CLI verification.
- Local server tests made real loopback HTTP requests and checked Host/Origin/key validation, rejection before oversized reads, route restrictions, and actual file inspection.

The remote cloud browser cannot reach this development container's loopback server. Interactive browser/visual verification has not been completed here. The UI must receive a clean-machine user walkthrough before a wider launch. No published screenshot should be represented as proof of end-to-end browser interaction.

The test corpus uses synthetic, harmless data. This is not a malware detection benchmark, independent security audit, or proof of resistance to all malicious archives. Hosted CI results are recorded by GitHub Actions, not inferred from these local results.

## v0.2.0 local validation

45 Python tests pass, including a real 25 MiB ZIP, HTTP upload above the former limit, rejected oversized request, and temporary cleanup after success/failure. JavaScript VM checks cover session-key refresh restoration, replacement by a new startup key, and unavailable storage. A 512 MiB sparse binary was hashed by the subprocess within its memory limit and returned explicit incomplete coverage. This boundary check is not a benchmark for all real-world archives. Browser visual interaction and hosted OS-matrix results must be checked separately.

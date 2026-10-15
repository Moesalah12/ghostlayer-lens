<p align="center"><strong>G H O S T L A Y E R &nbsp; L E N S</strong></p>
<h1 align="center">Know what’s inside.<br>Before you open it.</h1>
<p align="center">Local ZIP and script inspection with readable evidence and explicit coverage gaps.</p>
<p align="center"><a href="https://github.com/Moesalah12/ghostlayer-lens/actions/workflows/tests.yml">Tests</a> · <a href="docs/THREAT-MODEL.md">Threat model</a> · <a href="docs/RULES.md">Detection rules</a> · <a href="docs/ROADMAP.md">Roadmap</a></p>

**Early release · v0.1.0.** Lens is a static inspection and triage tool. It does not certify files as safe, replace antivirus, execute samples, or prove that a matched command will run. It has not received an independent security audit.

## What it does

Drop in a ZIP or readable script. Lens inventories the contents, highlights concrete review signals, and shows the file and excerpt behind each finding. It explicitly identifies what it could not inspect.

- Flags document-like names ending in executable extensions and bidirectional filename controls.
- Identifies lexical download, dynamic-execution, startup, elevation, and selected security-setting instructions.
- Decodes bounded PowerShell Base64 arguments for review without running them.
- Displays referenced HTTP(S) addresses as text, never contacting them.
- Inventories nested ZIPs without extracting them to disk; enforces entry, size, ratio, depth, and time budgets.
- Marks encrypted entries, unsupported content, malformed archives, and reached limits as coverage gaps.
- Exports full evidence JSON or a reduced summary that omits filenames, hashes, excerpts, and addresses.

**Core inspection is local, free, and open source.** There is no account, mandatory AI model, API key, telemetry, or external lookup. Downloading the source or Python itself still requires a network connection.

## Start in two commands

Requires **Python 3.11+** and a browser. No runtime packages to install. Download this repository's source ZIP and extract it, or clone it:

```sh
git clone https://github.com/Moesalah12/ghostlayer-lens.git
cd ghostlayer-lens
python -m lens serve
```

On Windows, `py -3 -m lens serve` also works. Or double-click **start-lens.cmd** in the extracted folder. Keep the terminal open. Ctrl+C stops the app.

The app opens at a random `127.0.0.1` port with a per-session key in the startup URL fragment. That key is removed from the address bar after loading and kept only in page memory. Refreshing loses it; reopen the full startup URL from the terminal. Keep that URL private. The app binds only to loopback, checks Host/Origin, and requires the key for scans. **Do not expose or reverse-proxy this server.**

Click **Inspect the training ZIP** for a real scan of a harmless, in-memory fixture. Its script examples are comments and are deliberately flagged as lexical evidence. It contains a fictional `MZ` marker fixture, not a valid executable or real malware. Demo results come from the same engine as ordinary uploads.

## CLI

```sh
python -m lens scan path/to/download.zip
python -m lens scan path/to/script.ps1 --output report.json
```

Output files are created exclusively; existing reports are not overwritten. Use a different filename for each report. Keep reports private until reviewed: full reports can contain sensitive paths, script excerpts, and addresses.

| Exit | Meaning |
| --- | --- |
| 0 | No review-level rule matches and inspection remained within supported scope; not a safety guarantee |
| 1 | Review recommended or incomplete inspection |
| 2 | Usage/input error, timeout, or failure to produce a complete report |

## Try the reproducible examples

```sh
python scripts/make_demo.py
python -m lens scan examples/training.zip
python -m unittest discover -s tests -v
```

The generator creates only fictional training data and refuses to overwrite an existing training ZIP. It never executes the scripts or opens referenced addresses.

## Inspection limits

| Budget | Default |
| --- | --- |
| Input | 20 MiB |
| Content per ZIP entry | 2 MiB |
| Total decompressed bytes, including nesting | 32 MiB |
| Inventory nodes, including root | 500 |
| Archive levels processed | 3 |
| Declared entry compression ratio | 200:1 |
| Findings | 1,000 |
| Cooperative inspection time | 10 seconds |
| Parent-process wall timeout | 15 seconds |

Stored and DEFLATE ZIP compression are supported. UTF-8 and BOM-marked UTF-16 text are supported. ZIP containers are recognized by extension or common ZIP signatures. Opening Office or other ZIP-based containers only inspects their supported entries; it does not provide application-specific document analysis. Other binary formats are not fully analyzed. A small MZ/PE marker check is metadata, not full executable verification.

Each scan runs in a disposable subprocess. Linux additionally applies memory/CPU resource limits where available. **This is not a hardened OS sandbox** and does not protect against every interpreter/library exploit. Windows uses the subprocess wall timeout but does not have the Linux address-space cap in this release. See [the threat model](docs/THREAT-MODEL.md).

## Why the result says “review,” not “malware”

A legitimate installer may request administrator privileges. Documentation can contain suspicious command examples. Obfuscated code can evade lexical rules. Lens separates observed indicators from coverage gaps, exposes its rules, and does not convert “nothing detected” into “safe.” Read [RULES.md](docs/RULES.md) for false positives and exclusions.

## Contribute

Useful contributions include failing regression tests, sanitized false-positive examples, archive edge cases, accessibility improvements, and independently reviewed parsers. [CONTRIBUTING.md](CONTRIBUTING.md) explains the process. Never attach live malware or private evidence to public issues. Private reports: [SECURITY.md](SECURITY.md).

Created for **Mohammad Salah, Founder & CEO of GhostLayer Defense**. This release is not a customer deployment, independent audit, or claim of universal malware detection. MIT licensed. Third-party names in the documentation do not imply endorsement.

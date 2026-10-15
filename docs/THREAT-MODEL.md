# Threat model and privacy

## Intended use

A person explicitly selects one untrusted download for static, local triage. The attacker controls the filename and file bytes, including ZIP metadata, script text, and referenced addresses. The operator owns the computer and starts Lens from trusted source. This is an early release for evaluation, not an independently audited malware laboratory.

## Boundaries

1. The browser sends the selected bytes to a loopback-only Python process. The production app has no cloud backend, remote fonts, analytics, external scripts, reputation checks, or AI calls.
2. The local HTTP handler accepts only exact static asset routes or an authenticated scan endpoint. It never serves arbitrary filesystem paths. Scans require the expected Host, exact local Origin, and a random session key. The response forbids cross-origin embedding and script loading.
3. A single scan is processed at a time in a disposable subprocess. The parent enforces a 15-second wall timeout. Linux sets a 384 MiB address-space cap and 12-second CPU limit where supported. The engine has additional entry/decompression/depth budgets. Windows/macOS resource enforcement differs: do not assume the Linux memory cap is active.
4. ZIP entries are inspected in memory, never extracted to their named paths. Symbolic links are not followed. Only stored/DEFLATE methods are decompressed; encrypted entries are skipped. Python may parse the ZIP central directory before the inventory limit applies. The input limit and subprocess limits reduce, but do not eliminate, parser resource risks.
5. Supported text receives lexical checks. No sample is imported, evaluated, run, rendered as HTML, or handed to an operating-system opener. Extracted addresses are rendered as text and never requested. No signature, reputation, or authenticity claim is made.
6. Browser reports use DOM text nodes, never interpolate file content into HTML. The full JSON export requires explicit confirmation. Summary export omits names, hashes, excerpts, and addresses but still reveals aggregate findings.

## Residual risks

- Process separation is not a hardened sandbox. A vulnerability in Python, zlib, the browser, or Lens could have security impact. Use a disposable VM for high-risk unknown samples. Keep the operating system and Python patched.
- The app runs under the operator's account. A parser exploit could inherit its access. The worker has no seccomp, namespace, Job Object, capability, or network-denial sandbox. Normal code makes no external requests, but that is not a containment guarantee after exploitation.
- A local malicious process can interfere with local apps; the browser key is not protection against an already-compromised host. Keep the startup URL private. The key persists across refreshes in tab-scoped session storage.
- A slow connection can occupy the single-request server until the socket timeout; it is not a multi-user production service. Never expose the port or place it behind a public tunnel/reverse proxy.
- Lexical rules can match comments, strings, harmless administration, or documentation. They can miss aliases, concatenation, complex encodings, non-UTF text, novel behavior, and semantic context. PowerShell Base64 decoding is bounded and not recursive.
- Filesystem/thumbnail preview outside Lens may process files independently. Lens cannot prevent that. It does not quarantine, delete, repair, block, or neutralize files.
- Static input size and decompression limits can exclude important evidence. A worker crash or timeout yields no completed report rather than a clean result.
- Original files remain where the user put them. Browser uploads are streamed to a temporary local directory, removed after successful or failed inspection during normal operation. Abrupt process termination may leave temporary files. Reports exist in process/browser memory. Lens makes no secure-memory erasure guarantee; OS swap/crash dumps can retain data. Downloads are controlled by the browser.

## Reporting

Send sanitized vulnerability reports privately as described in SECURITY.md. Do not publish sensitive documents, real malware, session URLs, or private logs in an issue.

## Primary references

- [Python ZIP decompression pitfalls](https://docs.python.org/3.11/library/zipfile.html#decompression-pitfalls)
- [Python security considerations](https://docs.python.org/3/library/security_warnings.html)

Large ZIP inputs are read from disk. Non-ZIP files above 2 MiB are hashed and explicitly reported as uninspected content. The 512 MiB input allowance does not expand the 2 MiB per-entry or 32 MiB total decompression budgets. Temporary upload storage is not secure erasure.

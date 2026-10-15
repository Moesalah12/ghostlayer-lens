# Rules and report semantics

Every finding has a stable rule name, severity for attention, node ID, explanation, and (when relevant) excerpt and 1-based line number. At most three matches per lexical rule per text/decoded text are emitted. Excerpts are capped at 300 characters; filenames at 1,000; addresses at 500, with at most 30 extracted per text pass. Control and bidirectional characters are escaped for readable labels.

| Rule | Observed evidence | Important limits |
| --- | --- | --- |
| disguised_extension | Document/media-like extension before a recognized executable extension | Filename heuristic, not content verification |
| bidi_filename | Unicode bidirectional formatting/isolate controls | May have benign language/formatting uses |
| unsafe_archive_path | Absolute, drive-prefixed, or parent-traversal entry name | Lens never extracts; another extractor may handle it safely |
| duplicate_entry | Same raw ZIP name occurs twice | No Unicode/case-insensitive collision analysis yet |
| remote_retrieval | Selected download keywords or curl/wget followed by whitespace | Misses aliases; can match comments/docs |
| dynamic_execution | Selected IEX/Invoke-Expression/eval/exec forms | Not a parser; can match ordinary words or benign code |
| startup_reference | Selected Windows Run/Startup/scheduled-task syntax | Legitimate software frequently uses these mechanisms |
| security_setting | Selected Defender/firewall change syntax | Limited lexical patterns; not every change disables protection |
| elevation_request | Selected RunAs/requireAdministrator syntax | Elevation is not inherently malicious |
| encoded_powershell | Selected powershell/pwsh encoded argument form | Only bounded Base64/UTF-16LE decoding, one level |
| decoded_text | A decoded command excerpt | Evidence only, never executed |
| binary_extension_mismatch | MZ prefix on a name without common Windows binary extension | MZ alone does not prove a valid executable |

Rules with `_decoded` suffix matched inside decoded text. Line numbers for those findings refer to decoded text, not the original file. URL extraction reports strings, not valid/reachable/safe domains; it does not resolve shortened links or perform reputation lookups.

## Assessment and coverage are separate

- `review_recommended`: at least one high/medium attention finding. Not a determination of maliciousness.
- `no_rule_matches`: no high/medium matches among applied rules. Informational findings can still exist.
- `incomplete`: at least one content gap, reached finding budget, or truncated inventory. This may coexist with either assessment.
- `within_supported_scope`: the supported static checks completed for inventoried content. Not semantic program analysis or a security guarantee.

Nodes can be `inspected`, `partial`, `not_inspected`, or `metadata_only` (directory entry). Hashes are emitted only when bytes were read. The root hash identifies the selected input, not its trustworthiness. A root `partial` ZIP can contain both inspected and uninspected children. The `stats.findings` field includes informational items; the UI's review-signals count excludes them.

## Not implemented

Full PE parsing/signature validation, antivirus signatures, behavioral execution, malware-family attribution, document macros/JavaScript semantics, RAR/7z decompression, URL reputation, script AST/data-flow analysis, phishing screenshots, real-time blocking, or autonomous remediation. These must not be advertised as current capabilities.

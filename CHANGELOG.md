# 0.2.0

- Stream browser uploads to temporary disk storage; accept inputs up to 512 MiB.
- Read ZIP inputs from disk with existing bounded content inspection.
- Hash large non-ZIP files and report their content as uninspected.
- Preserve local session keys across refreshes in tab-scoped storage.
- Remove temporary upload files after normal success and failure.

# Changelog

## 0.1.1 — documentation update

- Updated public documentation and distribution metadata. Inspection behavior is unchanged.

## 0.1.0 — early evaluation release

- Local visual app and command-line inspection.
- Bounded ZIP inventory, nested inspection, filename review, and text evidence rules.
- Nonrecursive bounded PowerShell argument decoding.
- Explicit coverage gaps and private/reduced JSON exports.
- Subprocess timeout, loopback session protection, regression tests, and documented threat model.

No executable installer or independent audit is included in this release.

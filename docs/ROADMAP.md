# Roadmap

This is a direction, not a delivery or detection guarantee. Open issues should describe concrete behavior, a test fixture, and acceptance criteria.

## 0.1 — evaluation release

Local app and CLI; bounded ZIP/text inspection; lexical evidence; explicit gaps; JSON exports; regression tests. Gather usability feedback and false-positive cases. Do not claim production readiness or universal file safety.

## Before a wider launch

- Independent review of parser/process/browser boundaries.
- Verify installation and UI behavior on clean Windows and macOS machines.
- Expand regression/fuzz testing and publish a reproducible evaluation corpus using harmless data.
- Improve accessibility, keyboard navigation, and supported language/encoding handling.
- Build reproducible, signed distribution artifacts; document updates and verification.
- Validate demand with users before expanding formats or adding AI.

## Candidate later work

- Script AST analysis that distinguishes comments from executable statements.
- Reviewed PE metadata/signature analysis and format-specific document inspection.
- Strong OS sandboxing with documented platform-specific guarantees.
- Opt-in hash reputation lookups with a clear disclosure before any transmission.
- Plugin interfaces, internationalization, and maintained rule packs.

No “clean” badges, fabricated detection statistics, bought stars, or unsolicited bulk outreach.

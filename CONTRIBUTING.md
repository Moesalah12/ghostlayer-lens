# Contributing

Start with a focused issue explaining the user problem. Contributions should add a harmless regression fixture, describe false positives and limits, and preserve explicit inspection gaps. No live malware, private files, credentials, or third-party evidence in public issues.

```sh
python -m unittest discover -s tests -v
node --check lens/web/app.js
```

Python 3.11+; no runtime dependencies. Node is only needed to check/test the JavaScript during development. Run from the repository root. Security reports belong in the private channel in SECURITY.md.

Avoid introducing network lookups, sample execution, arbitrary extraction, telemetry, silent report sharing, or a blanket “safe” verdict. Changes to these boundaries need a threat-model update and independent review.

Treat community members with respect. Discuss evidence and code, not personal attacks. Project maintenance does not imply a guaranteed support contract.

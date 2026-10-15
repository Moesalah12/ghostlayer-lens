# Early-release sharing kit

## Public project link

https://github.com/Moesalah12/ghostlayer-lens

## Short announcement

I’m building GhostLayer Lens, a free, open-source tool for inspecting ZIPs and scripts locally before opening them.

It shows the file and excerpt behind each warning, and explicitly reports what it could not inspect. No cloud upload, account, or AI API key is required.

This is an early static-analysis release, not an antivirus replacement or a guarantee of safety. I’m looking for feedback on false positives, archive edge cases, and making security evidence understandable.

Source and instructions: https://github.com/Moesalah12/ghostlayer-lens

Built by Mohammad Salah / GhostLayer Defense with AI development assistance.

## 45-second demonstration outline

1. Start the app locally and show the no-cloud/no-execution explanation.
2. Click Inspect the training ZIP. State that it is harmless, fictional training data.
3. Select photo.jpg.exe. Show the misleading extension and the explicitly uninspected binary.
4. Select setup.ps1.txt. Show the matched comment and line number; explain why lexical rules can flag benign examples.
5. Show a coverage gap and the reduced-summary export.
6. Close on the source, threat model, and contribution request. Do not claim a real attack was detected.

## First feedback goals

- Five people independently start the tool and run the training scan.
- Record setup failures and confusing warnings with platform/Python version.
- Collect harmless false-positive examples; never solicit private files or live malware publicly.
- Resolve reproducible failures before broad promotion.
- Seek independent parser/security review and publish findings honestly.

## Outreach boundaries

This file is a prepared draft. It has not been sent to people or posted to social platforms. Publish from an identified owner account to a chosen audience, respect each community's self-promotion rules, and disclose the early-release status. No automated bulk messaging, bought stars, fabricated testimonials, or guaranteed adoption claims.

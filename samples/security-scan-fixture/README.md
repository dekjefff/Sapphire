# Isolated scanner validation fixture

This directory contains intentionally vulnerable, non-production sample code for validating Sapphire's static scanner pipeline.

- `unsafe-demo.js` contains a `eval()` call so the repository's Semgrep rule can report it. The function is never called by Sapphire or by this fixture.
- `package-lock.json` pins the intentionally vulnerable `minimist@1.2.5` package so Trivy can report a known dependency vulnerability from its local database. Do not install dependencies from this fixture.
- `fake-credential.txt` contains only the public AWS example access key ID `AKIAIOSFODNN7EXAMPLE`; it is not a credential and has no corresponding secret key.

Do not add real secrets, scripts, build steps, or executable test commands here. Scanner validation analyzes these files as data and must not execute them.

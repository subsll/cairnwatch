# Changelog

All notable changes to Cairnwatch are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-11-07

### Added

- TTY-aware terminal spinner showing case creation, email preservation,
  Envelode parsing, detection, model reasoning, per-domain passive DNS, report
  writing, Stratum reporting and verification.
- `--no-spinner` flag.

## [0.2.0] — 2026-11-07

### Added

- Deterministic phishing detection layer with technique IDs and evidence.
- Cloaking heuristics: link text/destination mismatch, shorteners, redirect
  parameters, hidden CSS, identical text with multiple destinations.
- URL, obfuscation, punycode/IP, header/auth, attachment, tracking and
  social-engineering indicators.
- `detections.json` and `detections.md` evidence artefacts.
- `detections_extract` model tool and report appendix.
- Detection counts in the run manifest.

## [0.1.0] — 2026-11-07

### Added

- OpenAI-compatible tool-calling harness for defensive email investigations.
- Envelode metadata extraction as a model tool.
- Subsoil passive-only DNS as a domain-allowlisted model tool.
- Stratum case creation, source preservation, analysis acquisition, report
  generation and verification.
- Authorization attestation and raw-email upload opt-in.
- Command journal and manifest with hashes.
- Mock-model end-to-end tests.

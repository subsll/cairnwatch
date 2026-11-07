# Security policy

## Reporting

Report security issues privately to the maintainer. Do not include real case
material, API keys or personal data in a public issue.

## Design boundaries

Cairnwatch is an orchestration harness, not a scanner. It only invokes the
configured Envelode, Subsoil and Stratum binaries with fixed argument shapes.

- Subsoil is always invoked with `--passive`; brute force, AXFR and HTTP probing
  are never requested.
- Model-selected domains are checked against an allowlist derived from the
  email and explicit scope.
- The model has no shell, filesystem or arbitrary HTTP tool.
- Raw email content is sent to the model only when explicitly enabled.
- API keys are read from the environment and are not written to the case.

An authorisation acknowledgement is required, but it is an attestation, not a
technical proof of authorisation. Operators remain responsible for scope,
lawfulness and data handling.

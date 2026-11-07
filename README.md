# Cairnwatch

**A small defensive email investigation harness for Envelode, Subsoil and Stratum.**

Cairnwatch gives an OpenAI-compatible analyst model a narrow, auditable toolset:
Envelode extracts email metadata, Subsoil runs passive-only DNS, and Stratum
preserves the source and every analysis artefact in a hash-chained case.

It is deliberately not another scanner. It is an orchestration layer for
authorised blue-team work.

## Safety gates

- `--authorized` is required. The attestation is recorded in the case.
- Raw email content is **not** sent to the model unless
  `--send-email-content` is supplied.
- Subsoil is always invoked in `--passive` mode. Cairnwatch never requests
  brute force, zone transfers, HTTP probes, SMTP connections or exploitation.
- The model may only pass domains extracted from the email, from links in the
  email, or from `--scope`. The tool validates the allowlist again at runtime.
- The model has no shell, filesystem, network or arbitrary-command tool. It can
  only call the three fixed functions described below.
- The model's report is evidence, not a verdict. An analyst must verify findings.

Use Cairnwatch only on email and infrastructure you own or are explicitly
authorised to investigate.

## Requirements

- Go 1.25 or newer to build.
- [Envelode](https://github.com/subsll/envelode) 0.1+ for email metadata.
- [Subsoil](https://github.com/subsll/subsoil) 1.4+ for passive DNS.
- [Stratum](https://github.com/subsll/stratum) 1.2+ for evidence and reports.
- An OpenAI-compatible chat-completions API key.

Install the tools:

```sh
go install github.com/subsll/envelode/cmd/envelode@latest
go install github.com/subsll/subsoil/cmd/subsoil@latest
go install github.com/subsll/stratum/cmd/stratum@latest
go install github.com/subsll/cairnwatch/cmd/cairnwatch@latest
```

Make sure Go's `bin` directory is on `PATH`:

```sh
export PATH="$(go env GOPATH)/bin:$PATH"
```

## Run

OpenAI:

```sh
export OPENAI_API_KEY="..."
cairnwatch run \
  --email suspicious.eml \
  --case ./cases/acme-phish-2026-11 \
  --case-name "ACME phishing — November" \
  --operator "Jane Doe" \
  --org "ACME Blue Team" \
  --authorized \
  --send-email-content
```

DeepSeek:

```sh
export DEEPSEEK_API_KEY="..."
cairnwatch run \
  --email suspicious.eml \
  --case ./cases/acme-phish-2026-11 \
  --case-name "ACME phishing — November" \
  --operator "Jane Doe" \
  --org "ACME Blue Team" \
  --authorized \
  --send-email-content \
  --base-url https://api.deepseek.com/v1 \
  --model deepseek-chat \
  --api-key-env DEEPSEEK_API_KEY
```

Any OpenAI-compatible endpoint works with `--base-url`, `--model` and
`--api-key-env`. API keys are read from the environment and never written to
the case or printed.

The case directory must not already contain a case. Cairnwatch creates it with
Stratum and preserves the source email before calling the model.

## What happens

1. Cairnwatch creates a Stratum case and adds the raw email.
2. Envelode runs with `--no-dns` to produce metadata-only JSON.
3. Cairnwatch extracts sender domains and link domains into an allowlist.
4. The model is asked to call `envelode_extract`, then `subsoil_passive_dns`
   for relevant allowlisted domains, then `submit_report`.
5. Subsoil runs with `--passive`, no brute force, no AXFR and no HTTP probes.
6. The model's Markdown report and a run manifest are written.
7. The whole analysis directory is added to the Stratum case.
8. Stratum generates Markdown/JSON reports and re-verifies the evidence chains.

## Tools exposed to the model

| Tool | Purpose |
| --- | --- |
| `envelode_extract` | Metadata-only email parse, authentication headers, IPs and sender domains |
| `subsoil_passive_dns` | Passive-only Subsoil run against one allowlisted domain |
| `submit_report` | Final Markdown report |

The model has no other tools.

## Outputs

```text
<case>/reports/cairnwatch-report.md   model report
<case>/reports/report.md              Stratum report
<case>/reports/report.json            machine-readable Stratum report
<case>/reports/MANIFEST.json          Stratum manifest
<case>/reports/SHA256SUMS             report checksums
<case>/evidence.jsonl                 evidence chain
<case>/custody.jsonl                  custody chain
```

The analysis work directory contains `envelode.json`, `subsoil/<domain>/`,
`journal.jsonl`, `manifest.json`, `scope.json` and `authorization.json`; all of
it is added to Stratum. Use `--keep-work` to retain the local copy, or
`--workdir <dir>` to choose it.

## Privacy and model handling

`--send-email-content` sends the raw email, including headers and body, to the
configured API provider. Email can contain personal data, credentials, client
material or malicious content. Use a provider and data-handling arrangement
appropriate for your organisation, or omit the flag and accept metadata-only
analysis.

Subsoil makes DNS queries and may contact the passive sources you configure
(default: `crt.sh,certspotter`). It does not contact the target's SMTP or web
services in this workflow.

## Evidence integrity

- The raw email is added to Stratum before analysis.
- Every command exit, duration and stdout/stderr hash is recorded in
  `journal.jsonl`.
- The final report hash is recorded in `manifest.json`.
- Stratum generates its own manifest and checksums and verifies both chains.

Metadata and model output can be incomplete or wrong. Cairnwatch does not
establish authenticity, attribution or legal admissibility.

## Options

```text
--email <file>              source email (required)
--case <dir>                new Stratum case directory (required)
--case-name <name>          case title
--operator <name>           operator (required)
--org <name>                operator organisation
--authorized                required authorisation acknowledgement
--send-email-content        send raw email to the model API
--scope <domain>            extra allowlisted domain (repeatable)
--base-url <url>            OpenAI-compatible base URL
--model <name>              model name
--api-key-env <name>        env var holding the API key
--envelode-bin <path>       Envelode binary
--subsoil-bin <path>        Subsoil binary
--stratum-bin <path>        Stratum binary
--subsoil-sources <list>    passive sources (default crt.sh,certspotter)
--max-steps <n>             model steps (default 8)
--max-email-bytes <n>       maximum email bytes (default 200000)
--timeout <duration>        overall timeout (default 10m)
--workdir <dir>             analysis work directory
--keep-work                 keep the work directory
```

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
make linux
```

The tests use a mock OpenAI-compatible server and synthetic Envelode, Subsoil
and Stratum executables. No network access or API key is required.

## License

MIT — see [LICENSE](LICENSE).

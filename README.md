# Cairnwatch

**A small defensive email investigation harness for Envelode, Subsoil and Stratum.**

Cairnwatch gives an OpenAI-compatible analyst model a narrow, auditable toolset:
Envelode extracts email metadata, a deterministic detector logs phishing
techniques, Subsoil runs passive-only DNS, and Stratum preserves the source and
every analysis artefact in a hash-chained case.

It is deliberately not another scanner. It is an orchestration layer for
authorised blue-team work.

## Safety gates

- `--authorized` is required. The attestation is recorded in the case.
- Raw email content is **not** sent to the model unless
  `--send-email-content` is supplied.
- **External LLM warning:** if you use a hosted third-party API, enabling
  `--send-email-content` sends the raw email (headers, body and any attachment
  data encoded in the message) to that provider. Prefer a local
  OpenAI-compatible model/server. See
  [Privacy and model handling](#privacy-and-model-handling).
- Subsoil is always invoked in `--passive` mode. Cairnwatch never requests
  brute force, zone transfers, HTTP probes, SMTP connections or exploitation.
- The model may only pass domains extracted from the email, from links in the
  email, or from `--scope`. The tool validates the allowlist again at runtime.
- The model has no shell, filesystem, network or arbitrary-command tool. It can
  only call the four fixed functions described below.
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

## Detection system

Before the model runs, Cairnwatch applies deterministic email-only heuristics
and writes a technique log. Each detection has a stable ID, technique,
severity, confidence, evidence and location.

| Technique | Examples |
| --- | --- |
| `CLOAKING` | Visible link text differs from the destination; URL shorteners; redirect parameters carrying nested URLs; hidden CSS around links; identical text pointing to multiple destinations |
| `OBFUSCATION` | `javascript:`/`data:` links; base64 or `atob`/`eval` HTML patterns |
| `MASQUERADING` | Punycode or non-ASCII hostnames |
| `URL_ANOMALY` | IP-literal URLs; userinfo before host; encoded URL structure |
| `AUTH_FAILURE` | SPF, DKIM or DMARC failure results in the parsed authentication headers |
| `HEADER_ANOMALY` | From and Return-Path domains differ |
| `CREDENTIAL_HARVEST` | Password input fields in email HTML |
| `PHISHING_LINK` | External links in the message |
| `PHISHING_ATTACHMENT` | Risky attachment extensions such as `.exe`, `.js`, `.docm`, `.zip` |
| `TRACKING` | 1x1 tracking-pixel-like images |
| `SOCIAL_ENGINEERING` | Urgency, credential, invoice/payment or MFA language |

The log is written to `detections.json` and `detections.md`, exposed to the model
as `detections_extract`, and appended to the final report under **Automated
Detection Log**. ATT&CK IDs are included where a reasonable mapping exists;
they are approximate and are not a claim of attribution.

**Cloaking limitation:** email-only analysis cannot observe cloaking that
changes by user-agent, source IP, geolocation, time or authentication state.
Cairnwatch does not fetch links or execute HTML/JavaScript. A dedicated
controlled browser/network comparison is required to validate live cloaking.
Absence of detections is not evidence that an email is benign.

## Progress display

On an interactive terminal Cairnwatch shows a spinner with the current stage:

```text
⠹ passive DNS: example.com  00:12
```

Stages include case initialization, source email preservation, Envelode parsing,
detection, model reasoning, each passive Subsoil scan, report writing, Stratum
report generation and evidence verification. The spinner writes only to stderr,
is hidden when stderr is not a terminal, and can be disabled with
`--no-spinner`.

## What happens

1. Cairnwatch creates a Stratum case and adds the raw email.
2. Envelode runs with `--no-dns` to produce metadata-only JSON.
3. The deterministic detector logs techniques and evidence.
4. Cairnwatch extracts sender domains and link domains into an allowlist.
5. The model is asked to call `envelode_extract`, `detections_extract`, then
   `subsoil_passive_dns` for relevant allowlisted domains, then `submit_report`.
6. Subsoil runs with `--passive`, no brute force, no AXFR and no HTTP probes.
7. The model's Markdown report and a run manifest are written.
8. The whole analysis directory is added to the Stratum case.
9. Stratum generates Markdown/JSON reports and re-verifies the evidence chains.

## Tools exposed to the model

| Tool | Purpose |
| --- | --- |
| `envelode_extract` | Metadata-only email parse, authentication headers, IPs and sender domains |
| `detections_extract` | Deterministic technique log with evidence and limitations |
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

The analysis work directory contains `envelode.json`, `detections.json`,
`detections.md`, `subsoil/<domain>/`, `journal.jsonl`, `manifest.json`,
`scope.json` and `authorization.json`; all of it is added to Stratum. Use `--keep-work` to retain the local copy, or
`--workdir <dir>` to choose it.

## Privacy and model handling

> **Do not send sensitive email to an unapproved third-party API.**
>
> When `--send-email-content` is enabled and `--base-url` points to an external
> provider (OpenAI, DeepSeek, OpenRouter, etc.), Cairnwatch sends the **raw
> email**—headers, body and any attachment data encoded in the raw message—to
> that provider. Even without `--send-email-content`, structured metadata,
> detection results and tool output are sent to the model endpoint.

**Use a local LLM wherever possible.** An OpenAI-compatible local server keeps
the email and derived data inside your environment:

```sh
# Local OpenAI-compatible endpoint; use the model name your server exposes.
export OPENAI_API_KEY=local
cairnwatch run \
  --email suspicious.eml \
  --case ./cases/local-analysis \
  --operator "Jane Doe" \
  --authorized \
  --send-email-content \
  --base-url http://127.0.0.1:11434/v1 \
  --model local-model
```

Local endpoints that do not require authentication still need a non-empty API
key environment variable; use a placeholder such as `local`.

If an external provider is unavoidable, use an organisation-approved service
and data-processing agreement, minimise the data sent, disable training or
retention where the provider allows it, and confirm that your authorisation
covers third-party processing. Email can contain personal data, credentials,
client material or malicious content.

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
--no-spinner                disable the terminal progress spinner
--verbose, -v               trace model-step metadata and tool activity to stderr
```


## Troubleshooting model-step failures

`model did not submit a report within the step limit` means the model used every
allowed model turn without calling `submit_report` or returning a non-empty final
report. Cairnwatch now adds the last finish reason, content length and tool names
to that error, and prints a final-step instruction asking the model to submit.

Rerun with `--verbose` (and usually `--max-steps 16`) to see:

- the response `finish_reason` and content length at each step;
- which tools the model called, including allowlisted domains;
- tool errors such as an empty report or a missing passive-DNS result;
- token usage and the final-step submit instruction.

Verbose output deliberately does **not** include the email body, report body,
tool arguments or tool results, but tool-call summaries can contain domain names.
It writes to stderr and disables the spinner so the trace stays readable.

If the trace shows the same discovery tool repeatedly, the model is looping rather
than reasoning to a conclusion. If it shows `submit_report` errors, fix that
precondition or prompt. If it shows repeated `tool_calls` with no `submit_report`,
try a model with more reliable OpenAI-style tool calling before increasing the
step count further.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
make linux
```

The tests use a mock OpenAI-compatible server, synthetic Envelode/Subsoil/Stratum
executables and cloaking fixtures. No network access or API key is required.

## License

MIT — see [LICENSE](LICENSE).

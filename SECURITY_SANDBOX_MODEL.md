# Security Sandbox Model

Veritas is designed so the product does not become a backdoor into a customer's Splunk environment.

The guiding rule is simple:

> Treat every external feed, log line, uploaded artifact, and analyst-provided text as untrusted evidence, never as instructions.

## Current Controls In This Build

The current implementation applies these containment principles:

- The dashboard does not execute evidence text.
- Evidence rendering escapes HTML before writing untrusted values into the browser.
- Splunk tokens are read from local environment variables and are not committed.
- `/api/health` reports configuration status without exposing secrets.
- Splunk MCP write tools are disabled by default unless `VERITAS_MCP_ALLOW_WRITES=true`.
- MCP HEC writes require explicit confirmation for ingestion.
- High-impact containment actions are simulated and non-destructive.
- The online feed fetcher uses HTTPS-only source URLs.
- The online feed fetcher allows only known Splunk attack-data hosts and paths.
- The online feed fetcher applies response-size and JSON-line limits.
- Online feed data is parsed as JSON data only; it is never evaluated as code or shell commands.
- Generated feed output is ignored by Git to avoid accidentally committing local evidence artifacts.

## External Feed Sandbox Boundary

For the online evidence-feed path, Veritas uses this control chain:

```text
Public attack-data source
  -> allowlisted HTTPS fetch
  -> size limit
  -> JSON-line parser
  -> schema normalization
  -> Veritas evidence event
  -> Splunk HEC
  -> read-only MCP search
  -> dashboard evidence threshold engine
```

The product should not ingest arbitrary files directly into Splunk without this normalization boundary.

## Suspicious File Handling Policy

If Veritas later accepts uploaded files, archives, email attachments, endpoint captures, or analyst-supplied evidence files, those files must go through a quarantine path before Splunk ingestion:

1. Store the original file in a quarantine directory or bucket that is not served by the web app.
2. Compute hash, size, MIME type, extension, and source metadata.
3. Enforce file size, file type, and decompression limits.
4. Never execute the file, load macros, run embedded scripts, or follow active content.
5. Parse the file in a separate low-privilege process or container.
6. Disable outbound network access for the parsing sandbox where possible.
7. Scan with defensive tooling such as AV/YARA when available.
8. Extract only normalized metadata and log facts into Splunk.
9. Send raw files to a dedicated malware-analysis system only if detonation is required.
10. Keep destructive response actions disabled unless an explicit production integration has been built and reviewed.

## Splunk Protection Principles

Veritas should protect Splunk as a critical customer system:

- Use least-privilege Splunk tokens.
- Separate HEC write credentials from REST search credentials.
- Restrict HEC tokens to the intended index, such as `veritas`.
- Prefer a staging or quarantine index for untrusted raw feeds before promotion.
- Keep dashboard searches read-only.
- Avoid passing untrusted text directly into SPL without escaping.
- Do not expose Splunk management ports or tokens to the browser.
- Log the source dataset, source URL, job ID, and evidence IDs for auditability.

## Honest Judge-Facing Wording

Use this wording:

> Veritas treats external evidence as hostile input. It fetches online sources through an allowlisted, size-limited, JSON-only normalization path before Splunk ingestion, keeps Splunk credentials server-side, routes dashboard evidence searches through the backend/MCP boundary, and keeps containment non-destructive in this build.

Avoid this wording unless a dedicated malware sandbox is implemented:

- "Veritas detonates malware."
- "Veritas safely executes suspicious files."
- "Veritas can analyze any arbitrary file type."
- "Veritas performs production containment."

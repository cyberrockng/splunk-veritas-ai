# Deployment Status

Veritas AI is currently optimized for a local hackathon demo:

```powershell
python server.py
```

Open:

```text
http://127.0.0.1:5173
```

## Current Status

| Item | Status |
| --- | --- |
| Local Python API | Implemented and tested. |
| Local browser frontend | Implemented and tested. |
| Mock-mode demo | Implemented and tested. |
| Optional Splunk REST/HEC demo | Implemented and tested locally. |
| GitHub Actions CI | Implemented for mock-mode smoke tests. |
| Deployment security tests | Implemented for static-file hardening, CORS, headers, and optional auth. |
| Private staging auth gate | Implemented with `VERITAS_AUTH_TOKEN`. |
| Public production deployment | Not implemented. |
| Vercel production deployment | Not implemented. |

## Vercel Boundary

`vercel.json` is only a safe starter configuration for static frontend preparation. It does not make the Python API run on Vercel.

A static Vercel deployment of this repository would not support the Python API endpoints unless one of these paths is implemented:

1. Convert the API endpoints in `server.py` to Vercel serverless functions.
2. Host the Python backend separately and point the frontend to that backend.
3. Build a static demo mode that uses mock evidence without the Python API.

## What To Claim

Use this wording:

> Veritas is a local demo with a tested Python API, mock-mode CI, and an optional local Splunk REST/HEC evidence path. Public deployment is prepared conceptually but not implemented yet.

## What Not To Claim

Do not claim:

- Production deployment.
- Live Vercel backend support.
- Public multi-user hosting.
- Production authentication.
- Real destructive containment.

## Minimum Pre-Deployment Checklist

Before any public deployment claim:

1. Choose the hosting path.
2. Implement API hosting for that path.
3. Configure environment variables without committing secrets.
4. Set `VERITAS_AUTH_TOKEN` and `VERITAS_ALLOWED_ORIGINS` for private staging.
5. Add production-grade authentication and authorization before public customer use.
6. Run smoke and deployment security tests against the deployed URL.
7. Confirm screenshots and README point to the correct deployed mode.

## Private Staging Settings

Use these environment variables before exposing Veritas outside a trusted laptop:

```text
VERITAS_AUTH_USER=veritas
VERITAS_AUTH_TOKEN=<long-random-staging-password-or-token>
VERITAS_ALLOWED_ORIGINS=https://your-staging-domain.example
SPLUNK_HOST=<staging Splunk management URL>
SPLUNK_TOKEN=<secret-managed Splunk token>
SPLUNK_HEC_URL=<staging Splunk HEC URL>
SPLUNK_HEC_TOKEN=<secret-managed HEC token>
```

With `VERITAS_AUTH_TOKEN` set, the server accepts Basic Auth, `Authorization: Bearer <token>`, or `X-Veritas-Auth: <token>`.

Run the deployment security test against staging:

```powershell
$env:VERITAS_BASE_URL="https://your-staging-domain.example"
$env:VERITAS_AUTH_TOKEN="<same-token>"
$env:VERITAS_EXPECT_AUTH="true"
python deployment_security_tests.py
```

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
4. Add production authentication and authorization.
5. Run smoke tests against the deployed URL.
6. Confirm screenshots and README point to the correct deployed mode.

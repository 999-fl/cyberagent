# CyberAgent Android alpha

No ads. No root requirement. Android 8+.

## Features
- OpenAI-compatible chat completions API (OpenRouter or compatible providers).
- Bounded AI function-calling loop (up to four rounds).
- DNS lookup, common-port TCP connect scan, HTTP(S) GET inspection.
- HTTP status, response headers, redirect-chain and TLS cipher reporting (where available).
- Activity/evidence log with in-app clearing and Android share-sheet export.
- API keys are session-only (not persisted).

## Scope and limitations
- Agent tool arguments are restricted to the configured target hostname. HTTP(S) inspection manually follows up to four redirects and blocks destinations outside that hostname.
- Tools are non-destructive: they do not submit credentials or run exploit payloads.
- Use only against systems you own or are explicitly authorized to assess.
- Android's sandbox limits shell, raw-packet access and packet capture; these are not provided.
- The app requests only the INTERNET permission; no location or storage permissions are needed for current functionality.
- Activity logs are limited in memory and are not automatically persisted.

## Build
`gradle assembleDebug`

GitHub Actions builds a debug APK artifact on push or manual run.

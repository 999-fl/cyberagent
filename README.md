# CyberAgent Android alpha

No ads. No root requirement. Android 8+.

Alpha functionality:
- Provider-compatible chat completion API (OpenRouter or other compatible service).
- Common-port TCP connect scan (limited port list).
- DNS lookup.
- HTTPS header/status inspection.
- Evidence/activity log.

Limitations / security:
- API keys are currently session-memory only (not persisted).
- This alpha does not yet have agent tool-calling/autonomous scan loops, APK analysis, file import, browser automation, packet capture or advanced scanning.
- Android sandbox limits shell and packet privileges. Root is not required for connect scans, but ICMP/raw packet techniques and packet capture are unavailable without additional privilege or VPN-based capture.
- Use only on networks and systems you own or have permission to test.
- HTTPS tool currently does GET and redirects are not followed.
- No credentials are sent to target during these checks.

Build:
`gradle assembleDebug`

GitHub Actions workflow builds a debug APK artifact on push or manual run.

## Alpha update (0.2)
- Bounded AI function-call loop (up to four tool rounds) using OpenAI-compatible chat completions.
- Agent tools are DNS lookup, modest TCP connect scan of common ports, and HTTP(S) GET inspection.
- Agent tool arguments are constrained to the entered target hostname; requests remain non-destructive and do not submit credentials or exploit payloads.
- Web inspector reports status, headers, redirect chain and TLS cipher (where exposed); redirects are limited to four hops and blocked if they leave the scoped hostname.

Build remains via the GitHub Actions workflow; this environment's build status must be checked independently. The loop currently does not persist API keys or logs across app restarts.

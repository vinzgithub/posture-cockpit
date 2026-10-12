# Security

## Reporting a vulnerability

Please report security issues privately, through GitHub's **"Report a vulnerability"** button (Security tab of this repository), rather than in a public issue. You will get an answer within a week.

## What Posture Cockpit does on the network

Scans are **passive**: DNS queries, a TLS handshake on port 443 (one per TLS version tested), and GET requests to the home page, `/.well-known/security.txt` and the MTA-STS policy, following at most four redirects inside the scanned domain. No port scan, no form submission, no attempt to exploit anything. HTTP requests carry the User-Agent `PostureCockpit/<version> (+https://github.com/vinzgithub/posture-cockpit)`.

Only scan domains you own or are allowed to check.

## How the application protects itself

- **Accounts**: scrypt password hashes; optional two-factor authentication (TOTP, RFC 6238) with single-use recovery codes stored as SHA-256 hashes; a code cannot be replayed; other browsers are signed out after a password or 2FA change.
- **Attempts**: after 5 failures from one address, sign-in is refused for 5 minutes; wrong passwords and wrong codes share the same counter, including on the settings pages.
- **Administration**: pages ask for the password again every 10 minutes; an account is deleted only after typing its name.
- **Sessions**: signed cookie, `SameSite=Lax`, `Secure` when `POSTURE_COCKPIT_COOKIE_SECURE=true`.
- **Forms**: a CSRF token on every form and every state-changing request.
- **Browser**: strict Content Security Policy (no inline script or style, nothing from other origins), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`.
- **API keys**: shown once, stored as SHA-256 hashes, revocable.
- **Container**: unprivileged user, read-only root file system, no capabilities (see `compose.yaml`).

## Third-party extensions

An extension is Python code that runs inside the application with its privileges. Install only extensions you trust, and read their code: the extension API asks them to stay passive, but cannot force them to.

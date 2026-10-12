# Security

## Reporting a vulnerability

Please report security issues privately, through GitHub's **"Report a vulnerability"** button (Security tab of this repository), rather than in a public issue. You will get an answer within a week.

## What Posture Cockpit does on the network

Scans are **passive**: DNS queries, a TLS handshake on port 443 (one per TLS version tested), and GET requests to the home page, `/.well-known/security.txt` and the MTA-STS policy, following at most four redirects inside the scanned domain. No port scan, no form submission, no attempt to exploit anything. HTTP requests carry the User-Agent `PostureCockpit/<version> (+https://github.com/vinzgithub/posture-cockpit)`.

Only scan domains you own or are allowed to check.

### Where a scan may connect (egress rule)

Users choose the names that are scanned, and the scanned servers choose where they redirect. Without a rule, anyone able to add a domain could make the server connect to its own administration ports, to the cloud metadata service or to machines of the local network (server-side request forgery). One rule, in `core/egress.py`, applies to **every** connection, in the network layer that every check goes through:

- a host name is resolved **once per scan**; each address is checked, and the socket is opened to **that checked address** (the name is only used for TLS SNI, certificate verification and the HTTP `Host` header). A DNS answer that changes between two questions (DNS rebinding) cannot lead elsewhere;
- redirections are not followed by the network layer: a check that follows one makes a new request, checked like the first;
- addresses are sorted into three zones, from explicit tables (IANA special-purpose registries), for IPv4 and IPv6 alike; IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they lead to:

| Zone | Examples | Internet mode (default) | Internal perimeter |
|---|---|---|---|
| Public | any routable address | allowed, ports 80 and 443 | allowed, ports of the perimeter |
| Internal | 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, loopback, documentation ranges | **refused** | allowed **only inside the perimeter's networks** |
| Forbidden | 0/8, link-local 169.254/16 and fe80::/10, multicast, reserved, cloud metadata (169.254.169.254, fd00:ec2::254, 100.100.100.200, 168.63.129.16…) | refused | refused |

- environment proxy variables (`HTTP_PROXY`…) are ignored: a proxy would connect in our place, out of reach of the rule;
- each scan has limits: a deadline per network operation, at most 400 DNS queries and 80 connections, a time limit per check; work still running at the end of a scan is cancelled;
- a refused connection makes the check **"not evaluated"**, with the reason, never a judgement on the domain.

The guarantee covers everything that goes through the extension API (`ctx.net`). An extension is Python code running with the application's rights: it could open a socket itself. Install only extensions you trust (see below). Running the container with its own network rules (firewall, Docker network) is a useful second barrier.

### Internal perimeters

Auditing private networks is **off** until the operator starts the instance with `POSTURE_COCKPIT_INTERNAL_SCANS=true`. Then an administrator (who typed their password again in the last ten minutes) describes each perimeter: networks (only inside the private ranges above, never loopback, link-local or the metadata services), internal DNS servers, ports, and an internal certificate authority. Domains of a perimeter are added, seen, scanned and reported on by administrators only; for any other account they do not exist (404, pages and API alike). Every internal scan, and every change to a perimeter, is written to the audit log. Reports of internal audits are marked "restricted distribution".

TLS verification is **never** turned off: an internal CA is added to the system's trusted authorities for the scans of its perimeter. The certificate check still says whether a certificate is trusted, and a technical failure (no answer) is reported apart from an invalid certificate.

### Resolvers

Internet scans use the system's resolvers unless `POSTURE_COCKPIT_NAMESERVERS` is set. When the instance runs inside a company network, set it to public resolvers: otherwise the internal resolver answers Internet scans, and the details page of a scan could show records of internal zones to non-administrators.

## How the application protects itself

- **Accounts**: scrypt password hashes; optional two-factor authentication (TOTP, RFC 6238) with single-use recovery codes stored as SHA-256 hashes; a code cannot be replayed; other browsers are signed out after a password or 2FA change.
- **Attempts**: after 5 failures from one address, sign-in is refused for 5 minutes; after 10 failures on one account name, for 15 minutes, whatever the address. Wrong passwords and wrong codes share the same counters, including on the settings pages. An unknown account name costs the same password check as a known one, so the response time does not tell which accounts exist.
- **Administration**: pages ask for the password again every 10 minutes; an account is deleted only after typing its name.
- **Audit log**: sign-ins (successful, failed, blocked), password, two-factor and API key changes, administration changes, perimeters, and every scan with its perimeter and origin (page or API), with the client address. No secret is ever written. Administrators read it in the administration; the most recent 20,000 entries are kept.
- **Scans**: at most `POSTURE_COCKPIT_MAX_CONCURRENT_SCANS` (4) at once on the instance and `POSTURE_COCKPIT_SCANS_PER_HOUR` (30) per account; beyond, the page says so and the API answers 429.
- **Sessions**: signed cookie, `HttpOnly`, `SameSite=Lax`, `Secure` when `POSTURE_COCKPIT_COOKIE_SECURE=true`.
- **Forms**: a CSRF token on every form and every state-changing request; redirections after a form only go to paths of the application.
- **Browser**: strict Content Security Policy (no inline script or style, nothing from other origins), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store`, and HSTS when served over HTTPS.
- **API keys**: shown once, stored as SHA-256 hashes, revocable; a key has the rights of its owner.
- **Data**: the data folder and the database are created readable by their owner only; before a schema migration, a copy of the database is written to `backups/`.
- **Container**: unprivileged user, read-only root file system, no capabilities (see `compose.yaml`).

## Third-party extensions

An extension is Python code that runs inside the application with its privileges. Install only extensions you trust, and read their code: the extension API asks them to stay passive and gives them a network layer that applies the egress rule, but cannot force them to use it.

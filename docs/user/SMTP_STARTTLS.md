# SMTP STARTTLS check (v0.7.0)

🇫🇷 [Version française](SMTP_STARTTLS.fr.md)

The **“SMTP encryption of the receiving servers (STARTTLS)”** check (`mail.smtp_starttls`) verifies that the mail servers that receive the domain's mail (its MX) offer **STARTTLS** on port 25 and present a **certificate valid for their name**. This is what a sender requires before delivering when the domain enforces encryption with **MTA-STS** in `enforce` mode.

This check is **optional and off by default**. It is the only check that connects to mail servers: every other check reads DNS, HTTPS and HTTP.

## What it does

When the probe is on, for each scan:

1. it reads the published MX, as the “Mail servers” check does;
2. it keeps **8 of them at most**, by preference; those beyond are listed in the notes;
3. it opens **16 connections at most** (8 at a time), alternating IPv4 and IPv6: one address of each MX before a second one of any of them;
4. on each connection: it waits for the `220` greeting, sends `EHLO <your name>`, asks for `STARTTLS`, negotiates TLS 1.2 or 1.3 and verifies the certificate (chain of trust, name of the published MX, dates);
5. **it stops there**: no `MAIL FROM`, no recipient, no message, then `QUIT`.

The whole probe takes `min(12 s, POSTURE_COCKPIT_CHECK_TIMEOUT − 2 s)`, that is 12 s with the default setting (15 s). What was observed before that deadline is kept.

The connections follow the **egress rule** of scans: public addresses only, port 25 only, never in an internal perimeter (the check is “not applicable” there).

## Turning it on

In the `.env` file (see [INSTALLATION.md](INSTALLATION.md#settings)):

```bash
POSTURE_COCKPIT_SMTP_PROBE=on
POSTURE_COCKPIT_SMTP_EHLO_NAME=probe.my-domain.com
```

then `docker compose up -d`.

- **The EHLO name is required** when the probe is on; it has no default. It is a fully qualified DNS name (at least two labels, ASCII, the `xn--` form for an internationalised name), with no space and no control character. Choose a name **you control**, ideally with a consistent address and reverse record: the probe introduces itself to the servers it contacts with this name.
- An invalid value **prevents startup**, with the variable and the reason in the log. The same goes for `POSTURE_COCKPIT_SMTP_PROBE` (only `on` or `off`) and for `POSTURE_COCKPIT_CHECK_TIMEOUT`, which must stay above 2 s when the probe is on.
- **Outgoing port 25 must be open** to the Internet. Many Internet providers and hosting companies block it. Without it, every scan ends “not evaluated” for this check (“port 25 unreachable or too slow”), which lowers the coverage: leave the probe off in that case.

When off, the probe contacts nothing. The check is “not applicable”, with the message “SMTP check not run: the probe is turned off on this instance”. It does not count in the score.

## What it concludes

| Result | When |
|---|---|
| OK | Every published address of every MX offers STARTTLS with a valid certificate. Or at least one address of each MX was verified, and what could not be is said in the notes |
| To improve | Certificate refused without an MTA-STS `enforce` policy in force; certificate valid but expiring within 20 days |
| Critical | A server does not offer STARTTLS; certificate refused while an `enforce` policy is in force (senders that apply it no longer deliver to that server) |
| Not evaluated | An MX gave nothing conclusive: port 25 blocked, timeout, SMTP refusal, `STARTTLS` refused, TLS negotiation not completed, ESMTP capabilities masked by an intermediate device, DNS error. **This is never presented as a defect of the server** |
| Not applicable | Probe off, internal perimeter, or a domain without inbound mail (no MX, or a null MX) |

The check weighs **5** in the score (Mail category; see [SCORING.md](SCORING.md#4-the-weights)). A proven defect is never hidden by a missing measurement elsewhere.

## Readiness for MTA-STS `enforce` mode

Next to the result, the details page, the PDF report and the API (`mail_enforce_readiness`) give a separate indicator:

| State | Meaning |
|---|---|
| Ready according to the measures made from this instance | Every published address verified, valid MTA-STS policy in `testing` mode covering every MX |
| Compatible with the enforce policy in force | The same, with the policy already in `enforce` |
| To fix | STARTTLS absent, certificate refused, or an MX not covered by the policy |
| Cannot be confirmed | Probe off, incomplete measurement, policy missing, in `none` mode, invalid or unreadable, an MX that is an alias (CNAME); every cause is listed |
| Not applicable | No inbound mail |

“Ready” is **not a guarantee of delivery**: port 25 reached from your instance does not prove that senders on the Internet reach it.

## Limits

- **Point of view of the instance.** The result depends on the network that hosts Posture Cockpit (filtering, IPv6 routing, ESMTP inspection). An unreachable address is “not evaluated”, not at fault.
- **Sample.** At most 8 MX and 16 connections per scan; what was not tested is listed, and the readiness then stays “cannot be confirmed”.
- **No verdict on TLS versions** in 0.7.0: a refused version or a TLS alert leaves the server “not evaluated”.
- **No active security testing, no relay test.** No message is sent; the probe looks for no vulnerability.
- **Bounded evidence.** The stored observations fit in 64 KiB; the lists of MX and MTA-STS patterns of the “Mail servers” and “MTA-STS” checks keep 16 entries (the most significant first), with the exact number of those left out.
- **Load.** Each scan may open up to 16 SMTP connections; scheduled scans and rechecks too. Scan quotas apply as usual.

## History and comparisons

Turning the probe on or off changes **what is measured**, not the domain. Two scans made with the probe in different states are therefore **not compared**: no score difference, no event. The history and Mission Control say so (“different measurement scope (SMTP probe turned on or off)”). This scope is read from the stored result of each scan, never from the current configuration. The API gives it in `smtp_probe.scope`: `on`, `off`, `internal`, or `absent` for a scan made before 0.7.0 (see [HOME_ASSISTANT.md](HOME_ASSISTANT.md#api-additions-in-07)).

Scans made with v0.6.x are not compared with those of v0.7.0 either, which judge with other rules (generation 5; see [SCORING.md](SCORING.md#version-07-smtp-check-and-generation-5)).

References: RFC 3207 (STARTTLS), RFC 8461 (MTA-STS), RFC 7505 (null MX), RFC 5321.

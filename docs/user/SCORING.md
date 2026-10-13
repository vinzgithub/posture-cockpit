# How the score is computed

🇫🇷 [Version française](SCORING.fr.md)

Posture Cockpit's score sums up a passive scan. It does not replace an audit: it says what could be checked from the outside, and how much of it. This page gives the exact rules, applied the same way on the plan, the domain list, the API, the PDF report and the history.

## 1. What becomes of each check

| Status | Meaning | In the score |
|---|---|---|
| Compliant | Nothing to do | Its full weight |
| To improve | Not dangerous in itself, but should be strengthened | Half its weight |
| Critical | Needs fixing | Nothing |
| Not evaluated | The check applies but could not be done: server silent, timeout, destination refused by the scan's rule, TLS version this machine can no longer test | Left out of the score, **lowers the coverage** |
| Not applicable | The check does not concern this domain: no website, no inbound mail, check made for the Internet in an internal audit | Left out |
| Information | Nothing to judge (where mail arrives, DKIM key not found under the usual names) | Left out |

The difference between "not evaluated" and "not applicable" is essential: a check that *should* have answered and could not is a gap in the evaluation, never a success.

## 2. Coverage

The **coverage** is the weight of the evaluated checks divided by the weight of the applicable checks (evaluated + not evaluated). It is shown with every score: "Coverage 92%: 18 checks evaluated out of 20".

## 3. Score and grade

The score is the share of the weight earned by the evaluated checks, from 0 to 100. The grade follows the score:

| Grade | Score | Label |
|---|---|---|
| A | 85 and above | Strong |
| B | 70 to 84 | Fair |
| C | 55 to 69 | Needs watching |
| D | 40 to 54 | Fragile |
| E | 25 to 39 | Exposed |
| F | below 25 | Critical |

Then two rules tied to the coverage:

- **below 50% coverage: "Not evaluated"**, without score or grade. Too little was checked to judge the domain; the problems found are still listed and need fixing;
- **below 90%: partial evaluation**. The score is given with its coverage, and the grade cannot be better than **B**: an A asserts that the domain was checked, not only that what could be checked was fine.

Coverage percentages are rounded down: 89.6% shows as 89%, never 90%.

## 4. The weights

Unchanged since version 0.1.0.

| Check | Area | Weight | Internal audit |
|---|---|---|---|
| Protection against spoofing (DMARC) | Mail | 10 | not applicable |
| Website certificate | TLS | 10 | yes |
| Allowed senders (SPF) | Mail | 8 | not applicable |
| Automatic switch to HTTPS | Website | 8 | yes |
| HTTPS required (HSTS) | Website | 6 | yes |
| TLS versions | TLS | 5 | yes |
| E-mail signature (DKIM) | Mail | 4 | not applicable |
| Content Security Policy (CSP) | Website | 4 | yes |
| Name servers | DNS | 4 | not applicable |
| DNSSEC signature | DNS | 4 | not applicable |
| Encryption required on delivery (MTA-STS) | Mail | 3 | not applicable |
| Certificate key | TLS | 3 | yes |
| Protection against framing (clickjacking) | Website | 3 | yes |
| File types respected (nosniff) | Website | 2 | yes |
| Software versions shown | Website | 2 | yes |
| Allowed certificate authorities (CAA) | DNS | 2 | not applicable |
| Mail servers (MX) | Mail | 1 | not applicable |
| Encryption reports (TLS-RPT) | Mail | 1 | not applicable |
| Referring address (Referrer-Policy) | Website | 1 | yes |
| Security contact (security.txt) | Website | 1 | not applicable |

The MX check is information as long as the mail servers can be reached; it only counts ("to improve") when one of them has no address.

## 5. The plan of fixes

Critical checks make the **priorities**, checks to improve the **improvements**, each sorted by effect on the score, then by speed. The points shown are cumulative: they add up exactly to the target score. When the domain is not evaluated, the tasks are still offered, without points, since there is no starting score.

## 6. What changed in 0.2.0, and why

| Before (0.1.0) | Since (0.2.0) | Reason |
|---|---|---|
| No check could be evaluated: 100/100, A | "Not evaluated" | A domain must never look secure because almost nothing could be checked (anomaly reproduced during the audit) |
| 19 checks in error and 1 compliant: 100/100, A | "Not evaluated" (coverage 5%) | Same |
| No indication of what was really checked | Coverage shown everywhere | Reading a score without knowing what it covers misleads |
| A possible with part of the checks only | A only from 90% coverage | An A must hold for the domain, not for a sample |
| "No website", "no mail" as information | "Not applicable" | Tell apart what does not apply and what informs |

The weights and the score formula do not change. Scans already stored were computed again with these rules during the upgrade: their score does not change when their coverage reaches 50%; below, they become "Not evaluated"; an A obtained with less than 90% coverage becomes a B. A copy of the database from before the upgrade is kept in `backups/`.

The check fixes of 0.2.0 (DMARC, SPF, framing, CSP… see the [CHANGELOG](../../CHANGELOG.md)) may, for their part, change the score of a new scan compared with the previous one: the diagnosis became more accurate, the domain did not change.

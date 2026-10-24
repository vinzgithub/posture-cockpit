# How the score is computed

🇫🇷 [Version française](SCORING.fr.md)

The score summarizes applicable checks actually measured on one domain, not the security of an entire information system.
A score of 90/100 therefore does not mean that your information system is 90% secure.
Coverage shows the weighted share of applicable checks that could be evaluated.
A non-applicable check is excluded; an error or blocked check leaves a missing measurement and lowers coverage.
A score may remain provisional or be withheld when observations are insufficient.
Some critical findings cap the score or withhold its letter even when other checks succeed.
The rules below are shared by the plan, domain list, API, PDF and history.

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

## 7. What changed in 0.3.x, and why

The weights, the score formula and the coverage rules do not change, and stored scans are not recalculated. These verdicts changed in 0.3.2; they may move the score of the next scan:

| Situation | 0.3.1 | 0.3.2 | Reason |
|---|---|---|---|
| DMARC `p=reject; pct=0` (or any `pct` below 100) | Compliant | To improve | RFC 9989 made `pct` historic, but receivers that still follow RFC 7489 select only that share of the failing mail for the policy (with `p=reject`, the rest should be quarantined; with `p=quarantine`, it goes through the usual filtering) |
| DMARC `pct=101`, `pct=abc` | Compliant | To improve (values to fix) | RFC 7489 §6.3: an integer from 0 to 100 |
| `http://` redirects to another site, `https://domain/` answers with a valid certificate | Critical | Compliant | Sending visitors to another site is a business choice; the domain's own HTTPS works |
| The same, `https://domain/` refuses the connection | Critical | Critical | The domain has no HTTPS of its own |
| The same, `https://domain/` does not answer | Critical | Not evaluated | No answer is not a verdict: nothing was observed |

The MTA-STS and TLS-RPT records are now read as their RFCs write them (extension fields, spaces around `;`): a record that 0.3.1 called invalid or missing may be found valid, and the reverse. Both stay "to improve" when they are not usable, so the score moves only when a record becomes valid.

For a domain whose `http://` redirects to another site and whose own HTTPS never answers, the web and TLS checks are all not evaluated: the score may now be absent (coverage below 50 %) where 0.3.0 and 0.3.1 gave one by counting the redirect as failed without any answer.

### DMARC: one verdict, notes

A check gives one verdict. For DMARC, it is chosen in this order: invalid policy, testing mode `t=y`, monitoring `p=none`, values that do not follow the standard, `pct` below 100, subdomains left out (`sp=none`), local records ignored. Since 0.3.2, the other anomalies of the record are added after the verdict as notes, on the plan, the technical page, the history and the PDF reports. They change neither the status nor the score.

Under `p=none`, the tool no longer offers to move to `p=quarantine` when no valid report address is published (new verdict "without a valid report address"): without reports, nothing can show that the real e-mail passes. It neither makes up nor chooses an address, and the record it offers is a full quarantine: no faulty value, no repeated tag, no `t` or `pct`; `sp` and `np` are kept as written. A repeated tag is reported: the DMARC syntax forbids it and some receivers may ignore the whole record (status and score unchanged in 0.3.2, a study is planned for 0.4).

### Synthetic DMARC scenarios

The healthy test world (100/100, A, coverage 100%), with only its DMARC record changed. These are test worlds, computed by the engine in `tests/test_dmarc_scenarios.py`, not measurements of real domains.

| DMARC record | 0.3.1 | 0.3.2 | Score 0.3.1 → 0.3.2 |
|---|---|---|---|
| `p=reject` | Compliant | Compliant | 100 → 100 |
| Inherited from a public suffix with `p=none` | To improve | To improve (advice: a policy of the domain's own) | 94 → 94 |
| `p=reject; pct=50` | Compliant | To improve (partial rejection) | 100 → 94 |
| `p=reject; pct=0` | Compliant | To improve (partial rejection) | 100 → 94 |
| `p=quarantine; pct=0` | Compliant | To improve (partial quarantine) | 100 → 94 |
| `p=reject; pct=abc` | Compliant | To improve (faulty values) | 100 → 94 |
| `p=none; pct=abc` | To improve (monitoring) | To improve (monitoring without reports) + note "faulty values" | 94 → 94 |
| `p=reject; t=y; pct=101` | To improve (testing) | To improve (testing) + note "faulty values" | 94 → 94 |
| `p=reject; t=y; pct=50` | To improve (testing) | To improve (testing) + note "partial rejection" | 94 → 94 |
| `p=quarantine; t=y; pct=50` | To improve (testing) | To improve (testing) + note "partial quarantine" | 94 → 94 |
| `p=reject; pct=50; sp=none` | To improve (subdomains left out) | To improve (partial rejection) + note "subdomains left out" | 94 → 94 |
| `p=none` without `rua` | To improve (monitoring) | To improve (monitoring without reports) | 94 → 94 |

## 8. Version 0.4: HTTPS availability and diagnostic coverage

The HTTPS root and its ten dependents share a per-address probe. A confirmed refusal
on every published address blocks the ten dependents; they are neither scored nor
counted as errors. Scoring coverage excludes them; diagnostic coverage includes their
weight in its denominator. The score is not evidence that blocked checks succeeded.

Three non-cumulative cap reasons share the same reference: dependency, certificate
authentication, obsolete protocol. The reference keeps non-HTTPS results, assumes the
HTTPS root compliant, and puts evaluated or blocked dependents at their declared floors.
The final score is min(raw, reference), rounded only once. Category scores are uncapped.

If no address supports modern TLS, at least one refuses or is obsolete, and another is
inconclusive (including incomplete DNS discovery), the score is provisional without a
grade. This is `undetermined`, not `not_evaluated`. It is not comparable to a graded
score. An available modern-TLS address plus an unknown address retains its grade.

Four indicators accompany the result: scoring coverage, diagnostic coverage, blocked
checks, and discovered/attempted/conclusive (host, address) pairs. Counts do not imply
complete DNS discovery. Sampling, incomplete discovery and deadlines are named.

A HTTPS recheck reruns the complete enabled family with a fresh probe (9 seconds),
then up to 15 seconds for its checks. All rechecks are saved together. The original
findings remain unchanged; the current assessment includes the latest rechecks.
Root fixes may have a gain interval and a provisional target because the blocked
measurements are not yet known. A certificate fix has an exact gain when all its
dependents were measured.

HSTS history is local observation, not browser state. Only an HSTS header received
with a verified certificate over modern TLS is retained. Its lifetime is capped at a
year. `max-age=0` removes it; an absent or invalid header does not. An ancestor policy
applies only with includeSubDomains. `preload` is an indication, not evidence of actual
browser list membership. Neither history nor attribution changes any verdict or score.

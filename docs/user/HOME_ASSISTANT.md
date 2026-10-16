# Home Assistant

🇫🇷 [Version française](HOME_ASSISTANT.fr.md)

Posture Cockpit offers a small JSON API. Create a key in **Settings → API keys** (it is shown only once).

## One sensor per domain

`secrets.yaml`:

```yaml
posture_cockpit_auth: "Bearer YOUR_KEY"
```

`configuration.yaml`:

```yaml
rest:
  - resource: http://192.168.1.20:8080/api/v1/domains
    headers:
      Authorization: !secret posture_cockpit_auth
    scan_interval: 3600
    sensor:
      - name: "Posture my-domain.com"
        unique_id: posture_my_domain_com
        unit_of_measurement: "/100"
        value_template: >-
          {{ (value_json.domains | selectattr('domain', 'eq', 'my-domain.com') | first).score }}
        # No score when the domain could not be evaluated: the sensor is then "unavailable".
        availability: >-
          {{ (value_json.domains | selectattr('domain', 'eq', 'my-domain.com') | first).score is not none }}
        json_attributes_path: "$.domains[?(@.domain == 'my-domain.com')]"
        json_attributes: [grade, evaluation, coverage, critical, to_improve, not_evaluated, certificate_days_left, scanned_at]
```

Each domain gives:

| Field | Meaning |
|---|---|
| `score` | 0 to 100, or `null` when the domain is **not evaluated** (less than half of the applicable checks could run, see [SCORING.md](SCORING.md)) |
| `grade` | A to F, or `null` |
| `evaluation` | `complete`, `partial` (coverage under 90 %: the grade cannot be better than B) or `not_evaluated` |
| `coverage` | Share of the applicable checks that could run, 0 to 1 |
| `checks_evaluated`, `checks_applicable` | The same, in number of checks |
| `critical`, `to_improve` | Checks to fix, to improve |
| `not_evaluated` | Checks that could not run (server silent, timeout, destination refused) |
| `certificate_days_left` | Days before the website certificate expires |
| `perimeter` | Name of the internal perimeter, `null` on the Internet |
| `scanned_at` | Time of the scan (UTC) |

Since 0.2.0, `score` can be `null`: an automation that compares it with a number should first check `evaluation`. Domains of internal perimeters are only listed for an administrator's key.

## A scan every month

```yaml
rest_command:
  posture_scan:
    url: "http://192.168.1.20:8080/api/v1/domains/{{ domain }}/scan"
    method: POST
    headers:
      Authorization: !secret posture_cockpit_auth
    timeout: 60

automation:
  - alias: "Posture Cockpit: monthly scan"
    triggers:
      - trigger: time
        at: "07:30:00"
    conditions:
      - condition: template
        value_template: "{{ now().day == 1 }}"
    actions:
      - action: rest_command.posture_scan
        data:
          domain: my-domain.com
```

## An alert

```yaml
automation:
  - alias: "Posture Cockpit: certificate about to expire"
    triggers:
      - trigger: template
        value_template: "{{ state_attr('sensor.posture_my_domain_com', 'certificate_days_left') | int(99) < 15 }}"
    actions:
      - action: notify.notify
        data:
          message: "The certificate of my-domain.com expires in less than 15 days."
```

The scan answers `429` with a `Retry-After` header when the instance already runs its maximum of scans, or when the key's account used its hourly share (`POSTURE_COCKPIT_SCANS_PER_HOUR`).

Without Home Assistant, the same monthly scan runs from cron:

```bash
curl -fsS -X POST -H "Authorization: Bearer YOUR_KEY" http://localhost:8080/api/v1/domains/my-domain.com/scan
```

### API additions in 0.4

Keep `score` and `grade` nullable independently. A provisional score can have a null
letter, `evaluation: "undetermined"` and
`grade_withheld_reason: "https_availability_undetermined"`. Do not compare it with a
graded score, infer a letter, or treat it as a failed scan.

New fields: `score_raw`, `score_cap`, `score_final` (unrounded 0–1),
`diagnostic_coverage`, `checks_blocked`, `cap_reasons`, `addresses_discovered`,
`addresses_attempted`, `addresses_conclusive`, `address_sampling_limited`,
`address_discovery_complete`, plus the `addresses` object (including deadline status).
For 0.3.x scans, without recalculation or database backfill, diagnostic_coverage equals
stored coverage (with the same API rounding), checks_blocked is 0, score_raw and score_final equal stored score/100
(or null when no score exists), and score_cap is null. Address counts remain null. `not_evaluated` counts only errors, excluding
blocked checks. Existing keys and authentication remain unchanged.


An unreadable stored analysis is isolated. The domains endpoint keeps returning valid
summaries for other domains and returns an entry with `domain`, `scan_id` and
`error: "scan_unreadable"` for the damaged one. Single-analysis requests return HTTP 409
with the same error code. No score is inferred from corrupted findings.

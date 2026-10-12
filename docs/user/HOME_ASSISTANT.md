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
        json_attributes_path: "$.domains[?(@.domain == 'my-domain.com')]"
        json_attributes: [grade, critical, to_improve, certificate_days_left, scanned_at]
```

Each domain gives: `score` (0 to 100), `grade` (A to F), `critical` (critical points), `to_improve`, `certificate_days_left` and `scanned_at`.

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

Without Home Assistant, the same monthly scan runs from cron:

```bash
curl -fsS -X POST -H "Authorization: Bearer YOUR_KEY" http://localhost:8080/api/v1/domains/my-domain.com/scan
```

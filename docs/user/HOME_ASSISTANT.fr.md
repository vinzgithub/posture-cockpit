# Home Assistant

🇬🇧 [English version](HOME_ASSISTANT.md)

Posture Cockpit expose une petite API JSON. Créez une clé dans **Réglages → Clés d'API** (elle n'est affichée qu'une fois).

## Un capteur par domaine

`secrets.yaml` :

```yaml
posture_cockpit_auth: "Bearer VOTRE_CLE"
```

`configuration.yaml` :

```yaml
rest:
  - resource: http://192.168.1.20:8080/api/v1/domains
    headers:
      Authorization: !secret posture_cockpit_auth
    scan_interval: 3600
    sensor:
      - name: "Posture mon-domaine.fr"
        unique_id: posture_mon_domaine_fr
        unit_of_measurement: "/100"
        value_template: >-
          {{ (value_json.domains | selectattr('domain', 'eq', 'mon-domaine.fr') | first).score }}
        json_attributes_path: "$.domains[?(@.domain == 'mon-domaine.fr')]"
        json_attributes: [grade, critical, to_improve, certificate_days_left, scanned_at]
```

Chaque domaine donne : `score` (0 à 100), `grade` (A à F), `critical` (points critiques), `to_improve`, `certificate_days_left` et `scanned_at`.

## Une analyse chaque mois

```yaml
rest_command:
  posture_scan:
    url: "http://192.168.1.20:8080/api/v1/domains/{{ domain }}/scan"
    method: POST
    headers:
      Authorization: !secret posture_cockpit_auth
    timeout: 60

automation:
  - alias: "Posture Cockpit : analyse mensuelle"
    triggers:
      - trigger: time
        at: "07:30:00"
    conditions:
      - condition: template
        value_template: "{{ now().day == 1 }}"
    actions:
      - action: rest_command.posture_scan
        data:
          domain: mon-domaine.fr
```

## Une alerte

```yaml
automation:
  - alias: "Posture Cockpit : certificat bientôt expiré"
    triggers:
      - trigger: template
        value_template: "{{ state_attr('sensor.posture_mon_domaine_fr', 'certificate_days_left') | int(99) < 15 }}"
    actions:
      - action: notify.notify
        data:
          message: "Le certificat de mon-domaine.fr expire dans moins de 15 jours."
```

Sans Home Assistant, la même analyse mensuelle se lance avec cron :

```bash
curl -fsS -X POST -H "Authorization: Bearer VOTRE_CLE" http://localhost:8080/api/v1/domains/mon-domaine.fr/scan
```

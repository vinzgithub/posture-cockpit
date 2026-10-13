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
        # Pas de note quand le domaine n'a pas pu être évalué : le capteur est alors « indisponible ».
        availability: >-
          {{ (value_json.domains | selectattr('domain', 'eq', 'mon-domaine.fr') | first).score is not none }}
        json_attributes_path: "$.domains[?(@.domain == 'mon-domaine.fr')]"
        json_attributes: [grade, evaluation, coverage, critical, to_improve, not_evaluated, certificate_days_left, scanned_at]
```

Chaque domaine donne :

| Champ | Sens |
|---|---|
| `score` | 0 à 100, ou `null` quand le domaine n'est **pas évalué** (moins de la moitié des contrôles applicables ont pu être faits, voir [SCORING.fr.md](SCORING.fr.md)) |
| `grade` | A à F, ou `null` |
| `evaluation` | `complete`, `partial` (couverture sous 90 % : la lettre ne peut pas dépasser B) ou `not_evaluated` |
| `coverage` | Part des contrôles applicables qui ont pu être faits, de 0 à 1 |
| `checks_evaluated`, `checks_applicable` | La même chose, en nombre de contrôles |
| `critical`, `to_improve` | Contrôles à corriger, à améliorer |
| `not_evaluated` | Contrôles qui n'ont pas pu être faits (serveur muet, délai dépassé, destination refusée) |
| `certificate_days_left` | Jours avant l'expiration du certificat du site |
| `perimeter` | Nom du périmètre interne, `null` sur Internet |
| `scanned_at` | Heure de l'analyse (UTC) |

Depuis la 0.2.0, `score` peut valoir `null` : une automatisation qui le compare à un nombre doit d'abord regarder `evaluation`. Les domaines des périmètres internes ne sont listés que pour la clé d'un administrateur.

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

L'analyse répond `429` avec un en-tête `Retry-After` quand l'instance fait déjà son maximum d'analyses, ou quand le compte de la clé a utilisé sa part horaire (`POSTURE_COCKPIT_SCANS_PER_HOUR`).

Sans Home Assistant, la même analyse mensuelle se lance avec cron :

```bash
curl -fsS -X POST -H "Authorization: Bearer VOTRE_CLE" http://localhost:8080/api/v1/domains/mon-domaine.fr/scan
```

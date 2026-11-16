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
| `via` | Comment l'analyse a été lancée : `web`, `api` ou `schedule` ; `null` pour une analyse faite avant la 0.5.0 |
| `engine` | Génération des règles de notation qui ont jugé l'analyse ; `null` si elle est inconnue. Deux scores ne se comparent qu'à génération égale |

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

### Ajouts de l’API en 0.4

`score` et `grade` sont désormais indépendamment nullables. Un score provisoire peut
être présent avec `grade: null`, `evaluation: "undetermined"` et
`grade_withheld_reason: "https_availability_undetermined"`. Ne pas en déduire une lettre
ni le comparer à une note avec lettre.

Nouveaux champs : `score_raw`, `score_cap`, `score_final` (0–1 non arrondis),
`diagnostic_coverage`, `checks_blocked`, `cap_reasons`, `addresses_discovered`,
`addresses_attempted`, `addresses_conclusive`, `address_sampling_limited`,
`address_discovery_complete` et l’objet `addresses` (échéance comprise). Pour les analyses 0.3.x, sans recalcul ni écriture en base, diagnostic_coverage reprend
la couverture stockée (avec le même arrondi que coverage), checks_blocked vaut 0, score_raw et score_final valent le score
stocké divisé par 100 (ou null sans score), et score_cap vaut null. Les compteurs d’adresses
restent nulls. `not_evaluated` compte les erreurs,
sans les contrôles bloqués. Les champs existants et l’authentification sont conservés.

**Précision (0.4.1).** `coverage` et `diagnostic_coverage` sont des rapports entre 0 et 1 arrondis à
3 décimales (en 0.4.0, `diagnostic_coverage` ne l’était pas pour les analyses 0.4). Les pages et le
PDF affichent le pourcentage arrondi à l’entier inférieur : 0,8996 s’affiche « 89 % » alors que l’API
donne `0.9`. Comparez `coverage` aux seuils de la notation (0,5 et 0,9) plutôt qu’à un pourcentage arrondi.


Une analyse stockée illisible est isolée. L’API des domaines continue à fournir les
résultats des domaines sains ; l’entrée endommagée contient `domain`, `scan_id` et
`error: "scan_unreadable"`. Une requête sur cette analyse seule renvoie HTTP 409 avec
le même code. Aucune note n’est déduite de constats corrompus.

### Ajouts de l’API en 0.7

Deux objets s’ajoutent à chaque domaine ; aucun autre champ ne change. Ils sont lus dans le résultat enregistré du contrôle SMTP (voir [SMTP_STARTTLS.fr.md](SMTP_STARTTLS.fr.md)), jamais dans la configuration actuelle.

`smtp_probe`, toujours présent :

| Champ | Valeurs |
|---|---|
| `scope` | `on` (la sonde a mesuré), `off` (sonde désactivée : `status` `na`, `rule` `F05.01`), `internal` (périmètre interne), `absent` (analyse antérieure à la 0.7.0), `unknown` (erreur du moteur) |
| `status` | `ok`, `warn`, `fail`, `na`, `error`, ou `null` quand le contrôle est absent |
| `rule` | la ligne de décision, de `F05.01` à `F05.12`, ou `null` |
| `mx`, `addresses`, `verified` | MX publiés, adresses des MX mesurés, adresses dont le certificat a été vérifié ; `null` sauf si la sonde a mesuré |

`mail_enforce_readiness`, toujours présent :

| Champ | Valeurs |
|---|---|
| `state` | `ready`, `compatible`, `to_fix`, `unconfirmed` (cause `probe_off` quand la sonde était désactivée), `not_applicable`, ou `null` (contrôle absent, périmètre interne, erreur du moteur) |
| `causes` | liste des causes, comme sur la page de détail |
| `policy` | politique MTA-STS telle que la voient les expéditeurs : `enforce`, `testing`, `none`, `missing`, `invalid`, `unavailable`, `unreadable`, ou `null` quand aucune n’a été lue |

Une préparation est mesurée depuis cette instance : elle ne garantit pas la livraison depuis Internet. Ne comparez deux `score` qu’à `engine` et `smtp_probe.scope` égaux.

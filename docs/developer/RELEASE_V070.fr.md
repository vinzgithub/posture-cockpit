# Posture Cockpit v0.7.0 — dossier de livraison

**État : candidate v0.7.0, non publiée.** Cahier des charges révision 3 et plan en six PR (A, B1, B2, C, D, E) validés le 5 novembre 2026. Chaque PR a fait l'objet d'une contre-revue indépendante et a été fusionnée dans `integration/v0.7.0` avec l'accord explicite du mainteneur, sans réécriture d'historique. **Aucune publication et aucun déploiement n'ont été faits ; la production (v0.6.1) n'a pas été modifiée.**

## Périmètre livré

| Lot | PR | Contenu | Fusion |
|---|---|---|---|
| A | #44 | Réglages de la sonde SMTP (`POSTURE_COCKPIT_SMTP_PROBE`, `POSTURE_COCKPIT_SMTP_EHLO_NAME`), refus au démarrage, transmission aux contrôles | `b68723e` |
| B1 | #45 | Dialogue SMTP jusqu'à TLS, observé étape par étape (`core/smtp.py`) | `2c1991e` |
| B2 | #46 | Primitive réseau SMTP, règle de sortie (anti-SSRF), budget de 16 tentatives, orchestration | `6c9f321` |
| C | #47 | Verdict F05 et préparation à `enforce` F06, enregistrement du contrôle, génération 5, portée de mesure | `128c448` |
| D | #48 | Restitution : détail, annexe SMTP du PDF, champs de l'API | `ce07585` |
| Correction 1 | #49 | Tableaux du PDF à largeurs fixes | `0042c80` |
| Correction 2 | #50 | Preuve SMTP bornée à 64 Kio, compteurs exacts, preuve originale téléchargeable (A7) | `bdf94b2` |
| Correction 3 | #51 | Rapports PDF dans un processus séparé : limites de concurrence, de durée et de mémoire ; arrêt sûr | `e053283` |
| Correction 4 | #52 | Preuves et listes de `mail.mx` et `mail.mta_sts` bornées ; anciennes analyses bornées à la lecture | `c35fc56` |
| E | PR-E | Version 0.7.0, documentation FR/EN, notes de version, exemples régénérés, montée et retour depuis l'image officielle v0.6.1 en CI | — |

## Invariants et décisions

- `GENERATION = 5`, **21 contrôles**, schéma SQLite **5** (aucune migration depuis la 0.5.0).
- Sur les mondes de référence de la génération 4, la seule différence est la ligne « non applicable » du nouveau contrôle (`tests/data/generation-5.json`) : les autres contrôles jugent comme en 0.6.1.
- Sonde SMTP **désactivée par défaut**. Le nom EHLO est obligatoire quand elle est active, sans valeur par défaut. Adresses publiques et port 25 seulement ; jamais dans un périmètre interne ; `EHLO`, `STARTTLS`, `QUIT`, aucun message.
- F05 : une mesure manquante n'est jamais un défaut du serveur ; un défaut prouvé n'est jamais masqué par une mesure manquante. F06 : indicateur distinct du statut, jamais « prêt » sur un échantillon.
- `measurement_scope` : deux analyses de portées différentes (sonde activée ou non) ne sont pas comparées. La portée est lue dans la preuve stockée, jamais dans la configuration.
- API : deux champs ajoutés (`smtp_probe`, `mail_enforce_readiness`), aucun autre changé.
- Pas de version candidate sur GHCR : recette sur image Docker locale et instance isolée, puis publication stable directe.
- La PR-E ne change aucun comportement de l'application. Elle ne touche que :
  - le numéro de version ;
  - la documentation ;
  - les exemples ;
  - le script de démonstration ;
  - un test de documentation ;
  - la recette Docker (pages vérifiées lors de l'aller-retour) ;
  - la matrice CI (montée depuis v0.6.1).

## Preuves obtenues

### `integration/v0.7.0` avant la PR-E (`c35fc56`)

- CI après fusion de la PR #52, [run 42781740396](https://github.com/vinzgithub/posture-cockpit/actions/runs/42781740396) : **11 tâches réussies**.
  - Python 3.11, 3.12 et 3.13 : 2 914 réussis et 1 ignoré chacun ;
  - suite dans l'image : 2 914 réussis ;
  - conteneur durci (`--read-only`, `/tmp` en mémoire, `cap_drop ALL`, `no-new-privileges`, uid 10001) : 64 tests PDF réussis ;
  - Chromium, retour arrière et montées depuis v0.3.0, v0.4.0, v0.4.1, v0.5.0 et v0.6.0 réussis.
- Rapports PDF :
  - deux rapports lourds simultanés : `/healthz` à 92 ms au maximum, 3 ms en médiane (12 989 ms avant la correction 3) ;
  - refus immédiats en 5 à 6 ms ;
  - aucun processus de rapport restant après SIGTERM ou SIGKILL de l'application.
- Domaine de 3 001 MX :
  - preuves de 140 721 → 715 octets (`mail.mx`) et de 62 092 → 868 octets (`mail.mta_sts`) ;
  - rapport PDF de 116 → 4 pages ;
  - verdicts, `n` et notes identiques.

### PR-E

- Ruff, mypy et pytest local (Python 3.13) : voir la description de la PR.
- PDF de démonstration régénérés en v0.7.0 : **57/C**, comme en v0.6.1 ; 4 pages par langue ; annexe des 21 contrôles, le contrôle SMTP « non applicable » ; aucune valeur `None` ; marque fictive visible ; huit pages rendues et inspectées.
- CI de la PR-E, dont la montée et l'aller-retour depuis l'image officielle v0.6.1 : voir la description de la PR. Résultats à reporter ici avant la publication.

## Risques résiduels acceptés

1. **PDF de noms MX très longs.** Avec 16 noms de MX d'environ 210 caractères, le rapport fait 11 pages (77 avant la correction 4) : les colonnes étroites les replient ligne à ligne. Les scénarios volumineux de référence tiennent en 4 pages.
2. **« … » sans compteur dans certains textes.** `mail.mx.list`, `mail.mx.address` et le message au prestataire affichent 16 noms puis « … » sans total. Le nombre exact est dans `params.omitted`, et `n` dans le constat pour `unresolved` et `mx_mismatch`. L'afficher demanderait de nouveaux textes.
3. **`InvalidStateError` d'asyncio** dans certains tests d'annulation forcée. Ce bruit de test était déjà présent avant la PR #52 ; il est sans effet sur les résultats ni sur l'application.
4. **Pas de verdict sur les versions de TLS du SMTP** (F05.05 réservé) : un refus de version ou une alerte TLS laisse le serveur « non évalué ».
5. **Point de vue de l'instance.** La sonde mesure depuis le réseau qui héberge Posture Cockpit. Le port 25 joint ne prouve pas la livraison depuis Internet ; un port 25 bloqué rend le contrôle « non évalué » et fait baisser la couverture.
6. **Nouvelles analyses sans liste complète.** Comme pour SMTP, elles ne conservent pas les listes complètes de MX et de motifs : seuls 16 éléments déterminants et les comptes exacts sont gardés. Les analyses antérieures gardent leur original en base.
7. **Preuves SPF, DMARC, CAA et TLS-RPT non bornées** (D3) : chacune est limitée par une réponse DNS (64 Kio au plus) et n'est pas imprimée dans le PDF.
8. **Processus de rapport : un durcissement, pas un bac à sable.** Il tourne sous l'utilisateur de l'application. Si `prctl(PR_SET_PDEATHSIG)` est refusé, le refus est journalisé, et le processus reste borné par son temps processeur et ses tubes.
9. **Montée de la PR-E et pages de l'ancienne image.** L'aller-retour vérifie que l'ancienne image affiche les pages et l'historique des analyses de la candidate (HTTP 200). Le contenu rendu par la 0.6.1 pour le contrôle SMTP, qu'elle ne connaît pas, n'est pas inspecté visuellement en CI. Il est à regarder lors de la recette sur copie.

## Recette finale à mener (préparation)

Elle se fait après la fusion de la PR-E, sur le commit fusionné, et **sans toucher la production**. Chaque commande sera donnée une à une, marquée 🔎 (lecture) ou ⚠ (modification).

### 1. Image locale, instance Docker isolée

1. Construire l'image depuis le commit fusionné (`docker build -t posture-cockpit:0.7.0-recette .`) et vérifier `posture_cockpit.__version__ == "0.7.0"`.
2. `scripts/docker-recette.sh install posture-cockpit:0.7.0-recette` : installation neuve, code d'initialisation, sauvegarde, restauration, refus.
3. `scripts/docker-recette.sh upgrade <image officielle v0.6.1 par digest> posture-cockpit:0.7.0-recette` : montée, retour à la 0.6.1 sur le même volume, nouvelle montée, pages 200, `integrity_check=ok`.
4. `scripts/docker-recette.sh rollback` (vers la 0.4.1 par restauration), comme en CI.
5. Instance de test à la main (section « Une instance de test sur le même serveur » d'INSTALLATION) :
   - sonde désactivée : contrôle « non applicable », note inchangée ;
   - puis sonde activée avec un nom EHLO valide si le port 25 sortant est ouvert, sinon constater « non évalué » ;
   - refus au démarrage d'un nom EHLO invalide et d'une valeur de sonde invalide ;
   - rapports PDF FR/EN, deux simultanés et un troisième refusé ;
   - API `smtp_probe` et `mail_enforce_readiness`.

### 2. Copie restaurée de la production

1. Sauvegarde vérifiée de la production (lecture seule pour la production : `backup --output -`, `check-backup`), copiée hors du serveur.
2. Restauration dans une instance de test distincte (projet, conteneur, port, cookie et volume propres), en **v0.6.1** d'abord ; contrôle de `info`, des comptes, de la double authentification et des domaines.
3. Ordonnanceur désactivé, puis passage de cette instance en **v0.7.0** (image locale) :
   - `info` indique le schéma 5 à jour et aucune migration ;
   - historique conservé ; analyses 0.6.x affichées sans comparaison (« moteur d'évaluation différent ou inconnu ») ;
   - nouvelles analyses des domaines réels, sonde désactivée puis activée si possible ;
   - PDF FR/EN, API et Home Assistant si utilisé.
4. Retour de cette copie en **v0.6.1** : pages, historique et analyses 0.7.0 lisibles ; puis nouvelle montée en 0.7.0.

### 3. Critères de sortie

- Aucune erreur 500, aucun processus de rapport restant, `integrity_check=ok`, sessions et comptes intacts.
- Notes des contrôles existants identiques entre 0.6.1 et 0.7.0 pour une même observation, sonde désactivée.
- Aucune anomalie bloquante (sécurité, intégrité des données, verdicts, disponibilité, régression).

## Procédure de retour

- **Vers la 0.6.1, même schéma 5** : sauvegarde vérifiée hors volume, ordonnanceur désactivé, arrêt propre ; puis `compose.yaml` de la 0.6.1 (ou image officielle épinglée `sha256:f670500db50aff70b535a82ec0692660888f6b6387fbe25823feeb0a15d6f069`) sur le même volume. Aucune restauration n'est nécessaire, et les réglages propres à la 0.7.0 sont sans effet. Voir INSTALLATION, « Retour entre versions au schéma 5 ».
- **En dernier recours** : restauration de la sauvegarde faite avant la mise à jour (`restore --replace`), qui perd tout ce qui a été fait depuis (liste dans INSTALLATION, « Retour arrière »).

## Publication (à renseigner après les opérations)

Procédure : [RELEASE.fr.md](RELEASE.fr.md#publier-une-version).

- PR `integration/v0.7.0` → `main` : _numéro et SHA du commit de fusion, à renseigner après la fusion_.
- Tag `v0.7.0` et GitHub Release : _SHA du tag, lien et date de publication, à renseigner après la publication_.
- Workflow GHCR (`release.yml`, lancé à la main avec `PUBLISH_GHCR`) : _numéro de l'exécution, à renseigner après_.
- Digests relus de `0.7.0`, `0.7` et `latest` : _à renseigner après la publication_.
- Production : _migration distincte, sur autorisation, non comprise dans la publication_.

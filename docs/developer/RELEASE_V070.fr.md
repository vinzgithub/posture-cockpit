# Posture Cockpit v0.7.0 — dossier de livraison

**État : v0.7.0 publiée** (GitHub Release le 17 novembre 2026, image GHCR le 18 novembre 2026), après la recette finale du 16 novembre 2026. Cahier des charges révision 3 et plan en six PR (A, B1, B2, C, D, E) validés le 5 novembre 2026. Chaque PR a fait l'objet d'une contre-revue indépendante et a été fusionnée dans `integration/v0.7.0` avec l'accord explicite du mainteneur, sans réécriture d'historique. La production a été migrée séparément, le 18 novembre 2026 (voir « Publication »).

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
| E | #53 | Version 0.7.0, documentation FR/EN, notes de version, exemples régénérés, montée et retour depuis l'image officielle v0.6.1 en CI | `9c923ae` |

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

- Ruff et mypy propres ; pytest local (Python 3.13) : 2 913 réussis et 2 ignorés ; Chromium : 39 réussis.
- PDF de démonstration régénérés en v0.7.0 : **57/C**, comme en v0.6.1 ; 4 pages par langue ; annexe des 21 contrôles, le contrôle SMTP « non applicable » ; aucune valeur `None` ; marque fictive visible ; huit pages rendues et inspectées.
- CI du commit de fusion `9c923ae` ([run 43189879476](https://github.com/vinzgithub/posture-cockpit/actions/runs/43189879476)) : **12 tâches réussies**.
  - Python 3.11, 3.12 et 3.13 : 2 914 réussis et 1 ignoré chacun ;
  - suite dans l'image : 2 914 réussis ; conteneur durci : 64 tests PDF réussis ;
  - Chromium : 39 réussis ;
  - retour arrière et montées depuis v0.3.0, v0.4.0, v0.4.1, v0.5.0, v0.6.0 et v0.6.1 réussis, dont l'aller-retour v0.6.1 → 0.7.0 → v0.6.1 → 0.7.0 depuis l'image officielle épinglée par digest.

## Risques résiduels acceptés

1. **PDF de noms MX très longs.** Avec 16 noms de MX d'environ 210 caractères, le rapport fait 11 pages (77 avant la correction 4) : les colonnes étroites les replient ligne à ligne. Les scénarios volumineux de référence tiennent en 4 pages.
2. **« … » sans compteur dans certains textes.** `mail.mx.list`, `mail.mx.address` et le message au prestataire affichent 16 noms puis « … » sans total. Le nombre exact est dans `params.omitted`, et `n` dans le constat pour `unresolved` et `mx_mismatch`. L'afficher demanderait de nouveaux textes.
3. **`InvalidStateError` d'asyncio** dans certains tests d'annulation forcée. Ce bruit de test était déjà présent avant la PR #52 ; il est sans effet sur les résultats ni sur l'application.
4. **Pas de verdict sur les versions de TLS du SMTP** (F05.05 réservé) : un refus de version ou une alerte TLS laisse le serveur « non évalué ».
5. **Point de vue de l'instance.** La sonde mesure depuis le réseau qui héberge Posture Cockpit. Le port 25 joint ne prouve pas la livraison depuis Internet ; un port 25 bloqué rend le contrôle « non évalué » et fait baisser la couverture.
6. **Nouvelles analyses sans liste complète.** Comme pour SMTP, elles ne conservent pas les listes complètes de MX et de motifs : seuls 16 éléments déterminants et les comptes exacts sont gardés. Les analyses antérieures gardent leur original en base.
7. **Preuves SPF, DMARC, CAA et TLS-RPT non bornées** (D3) : chacune est limitée par une réponse DNS (64 Kio au plus) et n'est pas imprimée dans le PDF.
8. **Processus de rapport : un durcissement, pas un bac à sable.** Il tourne sous l'utilisateur de l'application. Si `prctl(PR_SET_PDEATHSIG)` est refusé, le refus est journalisé, et le processus reste borné par son temps processeur et ses tubes.
9. **Retour vers la 0.6.1 : affichage par la 0.6.1 des analyses de la 0.7.0** (contrôlé sur une copie de la production, voir la recette). Les analyses restent lisibles et gardent leur note, sans erreur. Mais la 0.6.1 affiche le contrôle SMTP par ses identifiants techniques (`mail.smtp_starttls.title`, `mail.smtp_starttls.ok`…), y compris dans une correction si la sonde avait relevé un défaut, et elle ignore la portée de mesure : entre deux analyses 0.7.0 faites sonde activée et sonde désactivée, elle affiche une évolution de note (« +1 points ») qui vient du réglage. Dès sa première analyse après le retour, plus aucune comparaison avec la 0.7.0. Limite documentée dans INSTALLATION (« Retour entre versions au schéma 5 »), sans correction : la 0.6.1 est publiée.
10. **Textes imprécis de la restitution SMTP.** La phrase « le port 25 joint depuis cette instance ne prouve pas… » s'affiche aussi quand aucun port 25 n'a été joint (sonde désactivée, adresses non autorisées), et la ligne « Limites de la mesure » n'accorde pas le singulier (« 1 adresses publiées »). Sans effet sur les verdicts ni sur la note.

Observation hors périmètre : la page d'historique porte deux attributs `style` bloqués par la politique de sécurité du contenu (`style-src 'self'`), en 0.6.1 comme en 0.7.0 ; défaut d'affichage mineur et ancien.

## Recette finale (16 novembre 2026)

Sur le LXC 119, qui héberge aussi la production, par décision du mainteneur ; instances distinctes (projets, conteneurs, ports, cookies et volumes propres), commandes Compose toujours écrites avec `-p`. La production n'a été que lue (une sauvegarde `backup --output -`) ; elle est restée en service, sans redémarrage.

- **Image** : `posture-cockpit:0.7.0-recette`, construite depuis `9c923ae` (`sha256:9bdebe81d2c0…`), version 0.7.0. Images de référence par digest : v0.6.1 `sha256:f670500d…` (celle de la production) et v0.4.1 `sha256:c5081ebc…`.
- **Recette scriptée** : `install` 24 vérifications, `upgrade` depuis v0.6.1 18 vérifications, `rollback` vers v0.4.1 31 vérifications ; mêmes nombres qu'en CI ; aucune instance restante.
- **Instance isolée** :
  - version 0.7.0 et schéma 5 ; compte et double authentification ;
  - sonde désactivée : contrôle SMTP « Non applicable », hors note et hors couverture ;
  - trois démarrages refusés avec un message clair (valeur de sonde invalide, sonde sans nom EHLO, nom EHLO invalide) ;
  - sonde activée : `gmail.com` « Conforme » (TLS 1.3, certificats vérifiés, IPv6 sans route listée comme non testée, 10 tentatives sur 16) ; un MX à adresse privée (DNS local) refusé par la règle de sortie et « Non évalué », sans défaut imputé ; comparaison refusée entre analyses de portées différentes ;
  - PDF FR/EN ; trois demandes simultanées par trois comptes : deux rapports, un refus immédiat (`busy`), aucun processus restant ;
  - API `smtp_probe` et `mail_enforce_readiness` conformes ; journal sans erreur 5xx.
- **Copie restaurée de la production** (1 compte, 9 domaines, 30 analyses) :
  - restauration en v0.6.1, `integrity_check = ok` ; montée en 0.7.0 sans migration ; historique 0.1.0 à 0.6.1 lisible, comparaison avec la 0.7.0 refusée (moteur différent) ;
  - notes identiques entre 0.6.1 et 0.7.0 pour une même observation, sonde désactivée : `finances.gouv.fr` 88 A et `clubic.com` 77 B, 20 contrôles sur 20 identiques, seule différence le contrôle SMTP « non applicable ». Deux analyses de `clubic.com` (site derrière Cloudflare) ont vu les contrôles web « non évalués » faute de réponse HTTP : une contre-épreuve en alternance 0.6.1 / 0.7.0 a montré la même instabilité du site dans les deux versions ;
  - sonde activée : `finances.gouv.fr` SMTP « Conforme » (F05.10), `clubic.com` « Non évalué » (F05.08) ;
  - retour en v0.6.1 sur le même volume, puis nouvelle montée en 0.7.0 : `integrity_check = ok` à chaque étape, 40 analyses ;
  - risque n° 9 : rendu et absence d'erreur 500 vérifiés (130 adresses, dont 49 PDF, toutes en 200 hors `/admin` en 303 de reconfirmation) ; comptes, rôles, domaines et clé de session identiques à la production ; écarts de lisibilité et de comparaison décrits au risque n° 9.

## Procédure de retour

- **Vers la 0.6.1, même schéma 5** : sauvegarde vérifiée hors volume, ordonnanceur désactivé, arrêt propre ; puis `compose.yaml` de la 0.6.1 (ou image officielle épinglée `sha256:f670500db50aff70b535a82ec0692660888f6b6387fbe25823feeb0a15d6f069`) sur le même volume. Aucune restauration n'est nécessaire, et les réglages propres à la 0.7.0 sont sans effet. Voir INSTALLATION, « Retour entre versions au schéma 5 ».
- **En dernier recours** : restauration de la sauvegarde faite avant la mise à jour (`restore --replace`), qui perd tout ce qui a été fait depuis (liste dans INSTALLATION, « Retour arrière »).

## Publication

Procédure : [RELEASE.fr.md](RELEASE.fr.md#publier-une-version).

- **PR #54** `release/v0.7.0` → `main` (contenu de `integration/v0.7.0` et commit documentaire `78f31c2`) : CI du HEAD réussie (25 vérifications) ; fusion par merge commit **`b04b6c7c61ed86575f08d8714b44e0f6bfaf2ca9`**, parents `fce2ec0` et `78f31c2`, arbre identique à `78f31c2`.
- **Tag `v0.7.0`** sur `b04b6c7` et **GitHub Release** [v0.7.0](https://github.com/vinzgithub/posture-cockpit/releases/tag/v0.7.0), publiée le 17 novembre 2026 à 06:59 UTC, version finale (non préversion), dernière version.
- **Workflow GHCR** `release.yml`, lancé à la main depuis `main` avec `release_tag=v0.7.0` et `PUBLISH_GHCR` : [exécution 44252216523](https://github.com/vinzgithub/posture-cockpit/actions/runs/44252216523), le 18 novembre 2026, 13 jobs réussis (suite Python 3.11 à 3.13, Chromium, Docker, retour arrière, montées depuis v0.3.0 à v0.6.1, image AMD64 et ARM64). État du registre avant publication : version absente.
- **Digests relus** : `0.7.0`, `0.7` et `latest` → `sha256:edc18c687847d2a9d1475d0f88fbfca117295eda0be7a998b0194e380982fd53`. Relecture indépendante : l'image téléchargée en production le 18 novembre 2026 porte ce même digest.
- Entre la GitHub Release (17 novembre) et le workflow GHCR (18 novembre), l'image `0.7.0` n'était pas encore publiée : une installation neuve pendant cet intervalle aurait échoué au téléchargement de l'image.
- **Production** (LXC 119), migrée le 18 novembre 2026, distinctement de la publication :
  - sauvegarde cohérente vérifiée par la v0.6.1 (1 compte, 9 domaines, 30 analyses ; SHA-256 `65fbf1e86152592d927a2fd9b642cbd53a2e87e46f9e02fdd928aaea894fe551`), copiée hors du conteneur LXC ;
  - `compose.yaml` de la v0.7.0 et `POSTURE_COCKPIT_IMAGE` passé à `0.7.0` ; ancienne configuration conservée ;
  - démarrage sain, schéma 5 à jour sans migration, `integrity_check = ok` ;
  - puis sonde SMTP activée et résolveurs publics (`POSTURE_COCKPIT_NAMESERVERS`) : le domaine du mainteneur, auparavant résolu en adresses privées par le DNS local, est mesuré comme depuis Internet, et son MX obtient « Conforme ».

# Posture Cockpit v0.6.1 — dossier de livraison

**État : version v0.6.1 validée et publiée le 24 octobre 2026 sur GitHub et GHCR.** Cahier des charges révision 3 validé techniquement par Claude ; intégration et publication approuvées par le mainteneur. **Aucun déploiement ni mise à jour d'une instance existante n'a été effectué.**

## Périmètre livré

| Lot | PR | Contenu |
|---|---|---|
| 1 | #33 | Cibles du plan et du PDF prudentes, FR/EN, T24 inchangé |
| 2 | #34 | Étapes MTA-STS/TLS : avertissements résiduels et perte du HTTPS moderne |
| 3 | #35 | `expect` explicite ; table courante prioritaire pour types intégrés reconnus, F05 bis |
| 4 | #36 | Gains hors effets inconnus, exclusions visibles ; cible complète et simulateur stricts |
| 5 | #37 | Images officielles v0.5.0/v0.6.0, recette 5→5 existante enrichie ; mode exécutable préservé |
| 6 | #38 | Gain exact, événements vides, compteur de priorités |
| 7 | #39 | Rapports fictifs FR/EN, guides, preuves et marqueurs de version 0.6.1 |

Les sept PR #33 à #39 ont été préparées en branches empilées, puis intégrées dans cet ordre à `main` avec l'accord explicite du mainteneur, sans réécrire l'historique. Le dernier merge est le commit `641f1dbde97e5e0166101f2c9c4f52b0ee6177fb`, identique au tag `v0.6.1`. Les commits distants sont attribués au compte `vinzgithub`, sans co-auteur.

## Invariants et décisions

- T01 identique à v0.5.0 ; `GENERATION=4` ; SQLite schéma 5 ; aucun nouveau contrôle ni fonctionnalité.
- Aucun diff des contrôles, du schéma, de l'API, de l'ordonnanceur, des règles d'événements, des droits ou des protections réseau.
- La table courante interprète en mémoire les actions intégrées reconnues, même si l'ancienne attente stockée vaut WARN/null. Les extensions inconnues gardent leur valeur explicite ; l'absence historique reste inconnue. Aucun JSON ancien n'est réécrit.
- A2 : les actions inconnues ne contaminent plus le cumul calculable ; elles restent dans la cible complète et la sélection explicite du simulateur. Elles sont nommées et les estimations partielles qualifiées dans CLI/web/PDF.
- SQL de comptage et injection du registre d'extensions dans le PDF reportés comme prévu. Le registre PDF intégré peut produire le repli FAIL pour des dépendants tiers inconnus ; aucune parité globale tiers n'est revendiquée.
- F12 : test additionnel du battement récent puis expiré à horloge explicite, sans écriture pendant les lectures et sans changement de l'ordonnanceur. Aucun contrôle d'exploitation de production n'est revendiqué.

## Preuves locales obtenues

- Suite complète finale locale : **1 781 réussis, 2 ignorés** en 119,99 s. Les deux cas ignorés sont explicites : machine disposant d’IPv6 (cas destiné à une machine sans IPv6) et processus root (test de refus d’écriture non applicable à root).
- Chromium avec transport de bouclage local : **29 tests réussis**, sans service ni domaine réel.
- Ruff et mypy : réussis ; tests de mise en page PDF et T01 réussis.
- Cinq tests F04 supplémentaires comparent les attentes SPF/DNSSEC/MX/MTA-STS/CSP avec les vrais contrôles sur réponses synthétiques, avant/après stockage historique et nouveau : réussis.
- Différentiel indépendant de celui de Claude : 20 000 cas, graine `6101`, cas tirés du corpus `tests/data/observation-v050-mc3.json`, statuts aléatoires (statut original conservé lorsque des signaux imposent un verdict). `assess` et `by_category` complets normalisés en JSON : empreintes identiques v0.5.0/candidate, `8e3c2d973bc0e0fd66d74c0a7d305b6b93e326e343b0eaf2e0d230bfeee70013`. Ce générateur ne prétend pas reproduire celui de Claude.
- Compatibilité au niveau du code : trois scans synthétiques avec extension `expect` OK/WARN/null, lecture et vraies écritures de revérification avec le tag v0.5.0 (`88623bccf9054b3fbbb1c360151efd27f467460f`), remontée candidate ; notes conservées et `integrity_check=ok`.
- Deux rapports PDF fictifs normaux, FR/EN, 57/C, quatre pages chacun ; texte extrait contrôlé et huit pages rendues/inspectées. Recette : [exemples](../examples/README.md).

## Preuves CI finales obtenues

**SHA applicatif et tests validés : `d7d21cd4bc5a957d336815a47dc462a68792f9f0`.** Arbre Git identique à l’environnement local : `4f9d7d63c650e5605380980dbf1f4bc3ba7b55b4`. La mise à jour de preuves de ce dossier est postérieure et documentaire uniquement ; elle ne change aucun code applicatif, test, image ou dépendance.

- [CI complète finale — run 40119185870](https://github.com/vinzgithub/posture-cockpit/actions/runs/40119185870) : **11 jobs réussis**, aucune étape requise en échec. Python 3.11/3.12/3.13, Chromium, Docker, cinq chemins upgrade et retour arrière.
- [Dry run multiarchitecture final — run 40119186044](https://github.com/vinzgithub/posture-cockpit/actions/runs/40119186044) : **réussi**, builds AMD64/ARM64, recette AMD64 et démarrage ARM64 émulé. Le job de tests réutilisé est intentionnellement ignoré dans ce workflow sur PR ; la preuve complète est le run séparé ci-dessus. Le registre de test est local à Actions : aucune publication GHCR.
- Jobs F08 finaux : `upgrade (v0.5.0)` **120946797200**, `upgrade (v0.6.0)` **120946797102**. Logs contrôlés : l’ancienne image redémarre sur les données de la 0.6.1, la candidate revient en 0.6.1, trois scans sont relus, `integrity_check=ok`, aucune restauration.
- Suite exécutée à l’intérieur de l’image : job **120946797085**, réussi.
- Les cas supplémentaires de cibles inconnues et conditionnelles sont rendus en vrais PDF FR/EN par les tests ; première page contrôlée. Quatre rapports de recette additionnels ont été rendus pour inspection visuelle, en plus des deux exemples publics.

Le code cumulé de #33–#38 et les compléments de #39 sont validés. Les premiers essais Actions ont détecté la perte du mode exécutable du script lors du transfert Git ; ce défaut de transfert a été corrigé par commits additionnels sans réécriture d'historique. Les exécutions antérieures en échec ne valent pas preuve de recette.

- Python 3.11/3.12/3.13, Ruff/mypy et tests applicatifs.
- Chromium, Docker installation et suite dans l'image.
- Upgrade historiques v0.3.0/v0.4.0/v0.4.1 et rollback avec restauration conservés.
- **F08 complète bloquante sur AMD64** : officielle v0.5.0 et v0.6.0 → candidate → ancienne image → candidate, même volume, sauvegarde vérifiée hors volume mais jamais restaurée pour cette preuve ; analyse sous candidate avec `expect`, analyse sous ancienne image, trois scans conservés, clé et intégrité contrôlées.
- ARM64 : build et démarrage émulé « quick » existants, dans le dry run du workflow release. **Limite : pas de F08 complète ARM64**, conformément à la spécification.
- Aucun test manuel avec lecteur d'écran réel n'est revendiqué. Docker n'est pas disponible dans l'environnement local : seule Actions peut fournir ici la preuve au niveau image.

## Procédure de retour documentée (sur copie isolée)

Sur copie isolée : sauvegarde vérifiée hors volume, ordonnanceur off, arrêt propre, image officielle v0.5.0 épinglée par digest sur le volume courant (schéma 5), contrôle de `info`, connexion/lecture/écriture et intégrité, arrêt puis remontée de l'image v0.6.1. Les projections anciennes DMARC de v0.5.0 peuvent réapparaître, pas une divergence des notes observées. Ne pas confondre ce retour avec le retour schéma 5→4 qui exige une restauration et perd les données post-sauvegarde.

Digest officiel v0.5.0 résolu directement auprès de GHCR : `sha256:c8dacc1e82646562a3a386ba850a8dca785df5ceee98bf9910ba74eef67a5651`. Image v0.6.0 : digest conservé de la publication vérifiée `sha256:70da24128abef742dc4649235d662a37596ed786a322d840c85aa02afc2fe633`. La CI vérifie aussi la version embarquée.

## Intégration et publication effectives

- **Intégration :** PR #33 à #39 fusionnées avec autorisation du mainteneur ; `main` et le tag `v0.6.1` pointent vers `641f1dbde97e5e0166101f2c9c4f52b0ee6177fb`. Le commit rassemble la candidate validée et ses preuves documentaires.
- **GitHub :** [release v0.6.1](https://github.com/vinzgithub/posture-cockpit/releases/tag/v0.6.1) publiée.
- **Publication GHCR distincte :** [workflow manuel #40123536677](https://github.com/vinzgithub/posture-cockpit/actions/runs/40123536677) **réussi**, 12 jobs terminés sans échec : tests Python 3.11–3.13, Chromium, Docker et migrations/retour arrière, recette AMD64 et démarrage ARM64 émulé, garde de version et lecture retour des tags.
- **Image multi-architecture :** `ghcr.io/vinzgithub/posture-cockpit:0.6.1`, digest `sha256:f670500db50aff70b535a82ec0692660888f6b6387fbe25823feeb0a15d6f069`. Les tags `0.6.1`, `0.6` et `latest` ont tous été relus avec ce même digest lors du workflow, après la publication du manifeste AMD64/ARM64.
- **Documentation :** PR #40 préparée pour synchroniser README FR/EN, guides et liens d'installation sur le tag publié `v0.6.1`, sans modification fonctionnelle du Compose.
- **Exploitation :** aucune instance existante n'est automatiquement migrée par la publication. Sauvegarde vérifiée et procédure de mise à niveau sont obligatoires avant une éventuelle intervention en production.

La recette F08 complète a été exécutée sur AMD64. ARM64 a été compilée et démarrée sous émulation, sans revendication de recette F08 complète sur cette architecture. Aucun test manuel avec lecteur d'écran réel n'est revendiqué.

# Posture Cockpit v0.6.1 — dossier de candidate

**État : candidate non publiée — 24 octobre 2026.** Aucun tag, release, publication GHCR ni déploiement réalisé. Le mainteneur a autorisé le développement après validation technique du cahier des charges révision 3 par Claude. Une autorisation de publication reste distincte.

## Périmètre livré

| Lot | PR | Contenu |
|---|---|---|
| 1 | #33 | Cibles du plan et du PDF prudentes, FR/EN, T24 inchangé |
| 2 | #34 | Étapes MTA-STS/TLS : avertissements résiduels et perte du HTTPS moderne |
| 3 | #35 | `expect` explicite ; table courante prioritaire pour types intégrés reconnus, F05 bis |
| 4 | #36 | Gains hors effets inconnus, exclusions visibles ; cible complète et simulateur stricts |
| 5 | #37 | Images officielles v0.5.0/v0.6.0, recette 5→5 existante enrichie ; mode exécutable préservé |
| 6 | #38 | Gain exact, événements vides, compteur de priorités |
| 7 | PR documentaire de candidate | Rapports fictifs FR/EN, guides, preuves et marqueurs de version 0.6.1 |

Les PR sont empilées : chacune cible la branche du lot précédent. Elles doivent être intégrées dans cet ordre sans réécrire l'historique. Les commits distants sont attribués au compte `vinzgithub`, sans co-auteur. Aucun merge implicite n'a été effectué pendant la préparation de ce dossier.

## Invariants et décisions

- T01 identique à v0.5.0 ; `GENERATION=4` ; SQLite schéma 5 ; aucun nouveau contrôle ni fonctionnalité.
- Aucun diff des contrôles, du schéma, de l'API, de l'ordonnanceur, des règles d'événements, des droits ou des protections réseau.
- La table courante interprète en mémoire les actions intégrées reconnues, même si l'ancienne attente stockée vaut WARN/null. Les extensions inconnues gardent leur valeur explicite ; l'absence historique reste inconnue. Aucun JSON ancien n'est réécrit.
- A2 : les actions inconnues ne contaminent plus le cumul calculable ; elles restent dans la cible complète et la sélection explicite du simulateur. Elles sont nommées et les estimations partielles qualifiées dans CLI/web/PDF.
- SQL de comptage et injection du registre d'extensions dans le PDF reportés comme prévu. Le registre PDF intégré peut produire le repli FAIL pour des dépendants tiers inconnus ; aucune parité globale tiers n'est revendiquée.
- F12 : vérification de la fenêtre de battement via les tests existants, sans changement de l'ordonnanceur. Aucun contrôle d'exploitation de production n'est revendiqué.

## Preuves locales obtenues

- Suite sur le code correctif avant marqueurs de version : **1 764 réussis, 2 ignorés**. Un second passage sur les marqueurs finaux est à consigner ci-dessous.
- Chromium avec transport de bouclage local : **29 tests réussis**, sans service ni domaine réel.
- Ruff et mypy : réussis ; tests de mise en page PDF et T01 réussis.
- Cinq tests F04 supplémentaires comparent les attentes SPF/DNSSEC/MX/MTA-STS/CSP avec les vrais contrôles sur réponses synthétiques, avant/après stockage historique et nouveau : réussis.
- Différentiel indépendant de celui de Claude : 20 000 cas, graine `6101`, cas tirés du corpus `tests/data/observation-v050-mc3.json`, statuts aléatoires (statut original conservé lorsque des signaux imposent un verdict). `assess` et `by_category` complets normalisés en JSON : empreintes identiques v0.5.0/candidate, `8e3c2d973bc0e0fd66d74c0a7d305b6b93e326e343b0eaf2e0d230bfeee70013`. Ce générateur ne prétend pas reproduire celui de Claude.
- Compatibilité au niveau du code : trois scans synthétiques avec extension `expect` OK/WARN/null, lecture et vraies écritures de revérification avec le tag v0.5.0 (`88623bccf9054b3fbbb1c360151efd27f467460f`), remontée candidate ; notes conservées et `integrity_check=ok`.
- Deux rapports PDF fictifs normaux, FR/EN, 57/C, quatre pages chacun ; texte extrait contrôlé et huit pages rendues/inspectées. Recette : [exemples](../examples/README.md).

## Preuves CI requises avant acceptation

Le SHA testé est celui de la tête de la PR de candidate, avec le code cumulé de #33–#38. Les premiers essais Actions ont détecté la perte du mode exécutable du script lors du transfert Git ; ce défaut de transfert a été corrigé par commits additionnels sans réécriture d'historique. Les exécutions antérieures en échec ne valent pas preuve de recette.

- Python 3.11/3.12/3.13, Ruff/mypy et tests applicatifs.
- Chromium, Docker installation et suite dans l'image.
- Upgrade historiques v0.3.0/v0.4.0/v0.4.1 et rollback avec restauration conservés.
- **F08 complète bloquante sur AMD64** : officielle v0.5.0 et v0.6.0 → candidate → ancienne image → candidate, même volume, sauvegarde vérifiée hors volume mais jamais restaurée pour cette preuve ; analyse sous candidate avec `expect`, analyse sous ancienne image, trois scans conservés, clé et intégrité contrôlées.
- ARM64 : build et démarrage émulé « quick » existants, dans le dry run du workflow release. **Limite : pas de F08 complète ARM64**, conformément à la spécification.
- Aucun test manuel avec lecteur d'écran réel n'est revendiqué. Docker n'est pas disponible dans l'environnement local : seule Actions peut fournir ici la preuve au niveau image.

## Procédure de retour prévue

Sur copie isolée : sauvegarde vérifiée hors volume, ordonnanceur off, arrêt propre, image officielle v0.5.0 épinglée par digest sur le volume courant (schéma 5), contrôle de `info`, connexion/lecture/écriture et intégrité, arrêt puis remontée candidate. Les projections anciennes DMARC de v0.5.0 peuvent réapparaître, pas une divergence des notes observées. Ne pas confondre ce retour avec le retour schéma 5→4 qui exige une restauration et perd les données post-sauvegarde.

Digest officiel v0.5.0 résolu directement auprès de GHCR : `sha256:c8dacc1e82646562a3a386ba850a8dca785df5ceee98bf9910ba74eef67a5651`. Image v0.6.0 : digest conservé de la publication vérifiée `sha256:70da24128abef742dc4649235d662a37596ed786a322d840c85aa02afc2fe633`. La CI vérifie aussi la version embarquée.

## Publication séparée

Les marqueurs sources (`pyproject.toml`, `__init__.py`, valeur par défaut Compose) sont préparés en 0.6.1 pour une candidate cohérente. Les commandes publiques des README et guides restent épinglées au tag publié v0.6.0. Pour tester la candidate, fournir une image locale/CI via `POSTURE_COCKPIT_IMAGE` ; ne pas prétendre que `ghcr.io/vinzgithub/posture-cockpit:0.6.1` existe déjà.

Après acceptation de la recette, présenter au mainteneur le SHA, les PR et les preuves. Tag, GitHub Release, publication GHCR et déploiement nécessitent son autorisation explicite. La CI sur PR n'utilise qu'un registre de test local pour son dry run de publication.

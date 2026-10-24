# Dossier de livraison — Posture Cockpit v0.6.0 « Mission Control »

> **PUBLIÉE LE 24 OCTOBRE 2026.** PR #31 fusionnée par squash (`2241e4b`), GitHub Release `v0.6.0` et images GHCR AMD64/ARM64 publiées par le workflow manuel [#78](https://github.com/vinzgithub/posture-cockpit/actions/runs/40090360219). Les trois tags `0.6.0`, `0.6`, `latest` pointent vers le même digest `sha256:70da24128abef742dc4649235d662a37596ed786a322d840c85aa02afc2fe633`. Tests GitHub, navigateur, Docker, migrations et rollback réussis. Aucun déploiement utilisateur n'est implicite. La recette avec lecteur d'écran reste à effectuer manuellement.

**Archives de préparation :** les preuves Work, contrôles intermédiaires et étapes à faire ci-dessous décrivent la situation *avant* la fusion et la publication. Ils sont conservés pour la traçabilité, non comme état actuel.

## Sources conservées

- Spécification définitive **MC-3**, socle : tag `v0.5.0` (`88623bccf9054b3fbbb1c360151efd27f467460f`), SQLite schéma 5.
- Correctif cumulatif **phases 1 à 5** : `mission-control-phases1-5.patch` (SHA-256 `add5b6b6dbf6c086ed7490f542afa2dcbc7a981ed138316b00915fb178f2746a`). Ne **pas** empiler avec les anciens patchs des phases 1–4.
- Recette de Work : `BILAN_PHASE5.md` et `preuves_phase5.zip`. Les assertions de tests sont celles de Work, non réexécutées ici dans leur intégralité.
- Complément phase 6 : `phase6-livraison.patch` — version 0.6.0 synchronisée (`pyproject.toml`, `__init__.py`, `compose.yaml`), changelog et dossier de livraison bilingue.

## Portée du développement

| Lot | Résultat attendu dans le correctif |
|---|---|
| MC01 | Changements vérifiables, dernier état concluant, interruptions d'observation distinguées |
| MC02 | Sélection multiple « Et si… ? », projections conditionnelles, remédiations DMARC par étapes |
| MC03–MC04 | Plan recalculé depuis l'état courant et explication textuelle des dépendances HTTPS |
| MC05 | Vue portefeuille paginée et contrôles d'autorisation avant agrégation |
| MC06 | Événements paginés et filtres |
| MC07 | Explication de la note et de ses limites en FR/EN et dans le PDF |

Aucun LLM, notification externe, correctif automatique, graphe complexe, contrôle SMTP port 25 ou score global inter-domaines n'est inclus.

## Contrôles obtenus lors de la phase 5 (selon le rapport Work)

- Python **3.11 / 3.12 / 3.13** : **1 727 tests réussis, 2 ignorés**, et **2 tests complémentaires réussis** par version (1 729 tests distincts au total par runtime).
- Chromium : **27 tests réussis** ; clavier, FR/EN, mobile, sans JavaScript et intégration des sélections.
- Ruff, mypy, paquet wheel et contrôles de base SQLite de la v0.5.0 : déclarés réussis.
- T01–T30 : recettes locales passées **à l'exception des validations image/CI/assistive** laissées partielles dans T21/T22.
- Retour arrière sur copies SQLite : **code v0.5.0** compatible avec le JSON de remédiation enrichi ; schéma **5** conservé.
- Portefeuille 1 000 domaines : résultat de profiling dans `preuves_phase5.zip` ; pas de mesure indépendante nouvelle ici.

## Vérifications indépendantes de la reprise (24 octobre 2026)

- Archive phase 5 retrouvée dans les fichiers utilisateur et empreinte SHA-256 du patch vérifiée.
- Correctif cumulatif : **53 chemins** modifiés/créés ; **20 nouveaux fichiers**, dont **16 fichiers Python** analysés syntaxiquement sans erreur et **un fixture JSON** valide.
- Arbres GitHub du tag v0.5.0 et de `main` comparés : les changements depuis le tag concernent `.env.example`, `CHANGELOG.md`, les deux README, les deux guides d'installation et deux guides v0.5.0 (`ANALYSES_PROGRAMMEES.md`, `EVENEMENTS.md`). **Aucun fichier du patch phases 1–5 n'entre en collision directe avec ceux modifiés sur main.** La vérification `git apply --check` doit néanmoins être refaite sur le clone exact avant toute PR.
- Le complément de version a été contrôlé par une application du patch sur un squelette représentatif ; **ce contrôle n'est pas une exécution sur la totalité du dépôt**.

## Points restants avant proposition de fusion

1. Sur une branche issue de `main` actualisé, appliquer le patch cumulatif phases 1–5, puis le complément phase 6. Garder les README pédagogiques de la PR #30.
2. Exécuter `python scripts/release_tags.py --image ghcr.io/vinzgithub/posture-cockpit --tag v0.6.0 --prerelease false` et vérifier les trois versions (pyproject, runtime, compose).
3. Installer les dépendances isolément et exécuter Ruff, mypy, pytest, Chromium. Comparer les résultats aux preuves phase 5.
4. Réaliser en **recette isolée** les tests Docker AMD64 et ARM64, y compris le retour arrière de l'image 0.6.0 vers 0.5.0 sur **copie** de base de données synthétique ; ne jamais employer la production.
5. Vérifier le rendu de la première page des PDF FR/EN et effectuer l'essai utilisateur au clavier et au lecteur d'écran (essai assisté non revendiqué).
6. Obtenir les contrôles CI obligatoires GitHub sur la future PR et contre-revoir le code structurellement modifié. Sans ces preuves, ne pas déclarer T21/T22 complètement réussis.
7. Prévoir une **PR documentaire après publication** pour basculer les commandes des README et guides publics de 0.5.0 vers 0.6.0 lorsque les images 0.6.0 existent sur GHCR. Elles restent volontairement sur la version disponible jusqu'alors.

## Décisions séparées

- **Autorisation 1 :** création du commit et de la PR candidate ; aucun commit/push/PR automatique ici.
- **Autorisation 2 :** fusion dans `main`, après tous les contrôles.
- **Autorisation 3 :** tag `v0.6.0` et GitHub Release.
- **Autorisation 4 :** publication manuelle des images GHCR avec `confirmation=PUBLISH_GHCR`, après vérifications amd64/arm64.
- **Autorisation 5 :** déploiement en production, sauvegarde vérifiée et retour arrière prévus.

**État lors de la passation, avant publication :** préparation et récupération du code achevées localement ; les contrôles Docker/CI et la publication ont depuis été réalisés comme indiqué en tête de ce document. Le contrôle par lecteur d'écran ne l'a pas été.

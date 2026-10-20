# Posture Cockpit v0.5.0 — dossier d'intégration (préparation)

**Statut : préparation, non publiée.** Ce dossier s'applique à la branche `feat/v0.5.0` et à la PR de publication #27. La version stable publique et la production demeurent **v0.4.1** tant que le propriétaire n'a pas expressément autorisé la livraison.

## Périmètre intégré

| Étape | Fonction | PR fusionnée dans `feat/v0.5.0` |
|---|---|---|
| 1 | Schéma SQLite 5, sauvegarde vérifiée avant migration, historique immuable et retour à 0.4.1 | #22 |
| 2 | Comparaison historique conservatrice et interfaces FR/EN | #23 |
| 3 | Analyses programmées, réservation transactionnelle, concurrence, heures locales et contrôles d'accès | #24 |
| 4 | Événements et alertes internes, filtres, lecture individuelle, droits des périmètres | #25 |

Le score, les règles de notation et les clés API historiques sont conservés. La migration de schéma 4 vers 5 est **irréversible sans restauration de la sauvegarde pré-migration**.

## Recettes antérieures — 19 octobre 2026

- Les quatre étapes ont été intégrées sur `feat/v0.5.0` sans divergence avec `main`.
- La dernière PR d'étape (#25) a été fusionnée au commit `fa033021c7800716bbf725c803d5b608bfe89363`.
- Les workflows `tests` et `release` (test de publication **à blanc** en PR) étaient verts sur le dernier commit de l'étape 4 avant sa fusion.
- Recette indépendante de l'étape 4 sur `l'instance isolée de recette (port 8085)` : `running / healthy`, API `/healthz` en v0.5.0. Les simulations SPF, couverture, trois échecs consécutifs, résolution et droits non administrateurs ont été validées. Les événements et programmations simulés ont ensuite été nettoyés par restauration d'une sauvegarde vérifiée.
- La production `la production (port 8080)` utilisait encore `ghcr.io/vinzgithub/posture-cockpit:0.4.1`, healthy. **Une recette intégrée distincte sur 8086 a ensuite été réalisée : voir ci-dessous.**

## Résultats complémentaires de recette intégrée — 19 octobre 2026

Les essais ci-dessous ont été exécutés **après la rédaction initiale** de ce dossier, sans modification de la production v0.4.1 sur le port 8080.

| Contrôle | Résultat vérifié |
|---|---|
| CI de la PR #26 à l'ancien HEAD `81a1b18` | [Workflow #39304603006](https://github.com/vinzgithub/posture-cockpit/actions/runs/39304603006) : **9 jobs réussis**, Python 3.11/3.12/3.13, Ruff, mypy, navigateur, Docker, migrations depuis 0.3.0/0.4.0/0.4.1, rollback |
| Recette intégrée | Image locale `posture-cockpit:v050-integration-8086` issue du commit `fa033021c7800716bbf725c803d5b608bfe89363`, conteneur `posture-cockpit-v050-integration-8086`, volume/Compose dédiés, `running / healthy` |
| Résultats et historique | `menuiserie-dupont.example` : **2 analyses à 57/100 (C)**, couverture de notation 100 % et 19/19 contrôles ; comparaison **delta 0**, sans faux événement |
| Événements | Régression SPF fictive : score **57 → 48**, incident `open / critical` ; restauration SPF : **48 → 57**, incident `resolved / info` ; « Marquer comme consultés » efface le badge mais conserve l'historique |
| Affichage et API | Parcours FR/EN vérifié ; API sans clé **401**, avec clé temporaire résultat attendu, après révocation **401** |
| Sauvegarde v0.5.0 | `backup` + `check-backup` réussis sur 8086, **schéma 5, 1 compte, 1 domaine, 2 analyses**, clé incluse |
| Ordonnanceur en recette intégrée | `POSTURE_COCKPIT_SCHEDULER=off` confirmé dans Administration ; programmation quotidienne 05:00 **inactive**, aucune échéance active ni exécution en erreur |

### Exécution effective du moteur de programmation, sans accès réseau

Essai isolé **hors 8086** : volume `pc-v050-scheduler-test-data`, conteneur temporaire `pc-v050-scheduler-execution-test` avec `--network none`, **sans port publié**, ordonnanceur **on**. Après création d'une analyse de référence fictive (`id=1`, `via=web`, score 57) et programmation quotidienne active avec échéance passée, puis délai de démarrage normal du moteur (**120 secondes**) :

- nouvelle analyse **`id=2`, `via=schedule`, score 57/100** ;
- `schedule_runs` : créneau local **`2026-10-19T22:27`**, état **`done`**, **1 tentative** ;
- conteneur arrêté puis supprimé ; volume de preuve conservé. L'ordonnanceur de 8086 est resté désactivé.

Il s'agit bien d'une **exécution déclenchée par le processus ordonnanceur**, mais les mesures du domaine utilisent les **réponses fictives intégrées**, pas Internet. Les simulations antérieures sur 8085 couvraient également les pertes de couverture, trois échecs programmés et la confidentialité des périmètres internes.

### Migration et retour arrière sur copie de la véritable production

1. **Source 0.4.1** : sauvegarde cohérente produite à chaud sur 8080 par `posture-cockpit backup`, puis vérifiée : `une archive vérifiée conservée hors dépôt` ; **schéma 4, 1 compte, 9 domaines, 26 analyses**, clé de session incluse.
2. **Copie isolée** : archive seule transférée depuis le volume de production monté **en lecture seule** vers `un volume de test dédié` ; fichier UID 10001 et permissions `0600` ; nouvelle vérification avec l'image officielle v0.4.1.
3. **État avant migration** : `restore` puis `info` sous v0.4.1 sur ce volume isolé : **schéma 4, 1 compte, 9 domaines, 26 analyses**, clé de session avec permissions `0600`.
4. **Migration de la copie** : image locale v0.5.0, `--network none`, ordonnanceur et analyses internes désactivés. Sauvegarde automatique avant modification : `une archive automatique avant migration du schéma`. Base migrée en **schéma 5**, **9 domaines et 26 analyses conservés**.
5. **Archive automatique vérifiée avec v0.4.1** : schéma **4**, 1 compte, 9 domaines, 26 analyses. La mention `version 0.5.0` désigne le programme qui a créé l'archive, **pas le schéma**.
6. **Intégrité SQLite après migration** : `PRAGMA integrity_check = ok`, `PRAGMA foreign_key_check` = **0 erreur**, **9 domaines et 26 analyses**. Le montage de test devait permettre les fichiers auxiliaires du mode SQLite WAL ; la connexion SQLite de contrôle est restée en lecture seule.
7. **Retour arrière réel sur la copie uniquement** : image v0.4.1, `restore ...before-schema5... --replace`. L'ancienne base migrée a été préservée dans `une archive avant restauration`.
8. **Résultat final de rollback** : `posture-cockpit info` sous v0.4.1 → **schéma 4 (up to date), 1 compte, 9 domaines, 26 analyses, clé présente en 0600**.

**Conclusion :** migration 4→5, intégrité, archive pré-migration et rollback 5→4 **validés sur une copie des données réelles** ; aucun démarrage de v0.5.0 sur la base active de production. Les archives contiennent des données et secrets réels : **ne pas les joindre à une PR, à un commit ou aux artefacts CI**.

## Barrières de validation avant livraison

- [x] CI complète de la PR #27 au SHA `115dc931...` : **9 jobs réussis** ([exécution](https://github.com/vinzgithub/posture-cockpit/actions/runs/39330902541)). Reconfirmer après toute correction du candidat.
- [x] Recette intégrée au commit `fa033021...` sur 8086, avec ordonnanceur et analyses internes explicitement désactivés.
- [x] Comparaison, FR/EN, API, incidents fictifs SPF ouverts et résolus, marqueur de consultation, sauvegarde.
- [x] Exécution effective de l'ordonnanceur dans un conteneur isolé, `via=schedule`, état `done`, une tentative.
- [x] Migration sur copie de production et intégrité SQLite, avec conservation des 9 domaines et 26 analyses.
- [x] Retour à 0.4.1 sur cette copie, confirmé avec l'image officielle.
- [x] Construction AMD64/ARM64 et garde-fous de publication à blanc au SHA `115dc931...` ([exécution](https://github.com/vinzgithub/posture-cockpit/actions/runs/39330902538)) ; registre local uniquement.
- [x] Horodatages de recette contrôlés : aucun état fictif daté dans le futur.
- [ ] Reconfirmer CI et publication à blanc sur le SHA définitif après corrections prépublication.
- [ ] Faire relire le dossier et les procédures par le propriétaire.
- [ ] Avant migration de production : **copie de sauvegarde vérifiée hors du volume de production**, espace libre, fenêtre de maintenance, procédure de reprise et décision explicite sur l'ordonnanceur.
- [ ] Autorisations distinctes pour la fusion de PR #27 dans `main`, le tag, la GitHub Release, le déclenchement manuel GHCR et toute migration de production.

## Précautions de publication

1. Garder pour l'instant la documentation de **démarrage rapide public** dirigée vers l'image et le tag `v0.4.1` : la 0.5.0 n'a pas encore de release publiée.
2. Fusionner la PR #27 uniquement après accord explicite. Demander ensuite des accords distincts pour le tag, la GitHub Release et les images GHCR.
   **La création de la GitHub Release ne publie pas les images :** sur autorisation séparée, déclencher manuellement le workflow `release` depuis `main` avec `release_tag=v0.5.0` et `confirmation=PUBLISH_GHCR`. Ce workflow revérifie la Release publiée, l'appartenance du commit à `main`, les tests, la recette Docker, les architectures AMD64/ARM64 et les digests. Les PR ne publient que vers un registre de test local.
3. Avant la mise à niveau de la production : capture/restauration testée des fichiers et des données, export externe de l'archive pré-migration, contrôle d'espace libre, fenêtre de maintenance, annonce de la désactivation ou activation contrôlée de l'ordonnanceur.
4. Après publication : les procédures d'installation publique pourront alors être actualisées pour `v0.5.0` (pas avant).

## Hors périmètre v0.5.0

Les libellés plus lisibles pour les identifiants techniques tels que `mail.spf` sont **reportés à une version ultérieure**, à la demande du mainteneur.

**Confidentialité :** aucune archive ni donnée brute de production ne doit être committée. L'anonymisation du présent document dans le dernier commit n'efface pas ses anciennes versions de l'historique Git.

**Ce document n'autorise à lui seul aucun déploiement et ne remplace pas les essais de la version intégrée finale.**

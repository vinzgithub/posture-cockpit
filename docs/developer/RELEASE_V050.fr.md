# Posture Cockpit v0.5.0 — dossier d'intégration (préparation)

**Statut : préparation, non publiée.** Ce dossier s'applique à la branche `feat/v0.5.0` et à sa branche documentaire `integration/v0.5.0-preparation`. La version stable publique et la production demeurent **v0.4.1** tant que le propriétaire n'a pas expressément autorisé la livraison.

## Périmètre intégré

| Étape | Fonction | PR fusionnée dans `feat/v0.5.0` |
|---|---|---|
| 1 | Schéma SQLite 5, sauvegarde vérifiée avant migration, historique immuable et retour à 0.4.1 | #22 |
| 2 | Comparaison historique conservatrice et interfaces FR/EN | #23 |
| 3 | Analyses programmées, réservation transactionnelle, concurrence, heures locales et contrôles d'accès | #24 |
| 4 | Événements et alertes internes, filtres, lecture individuelle, droits des périmètres | #25 |

Le score, les règles de notation et les clés API historiques sont conservés. La migration de schéma 4 vers 5 est **irréversible sans restauration de la sauvegarde pré-migration**.

## État contrôlé au 19 octobre 2026

- `feat/v0.5.0` est 98 commits en avance sur `main`, sans commits divergents (comparaison GitHub à cette date).
- La dernière PR d'étape (#25) a été fusionnée au commit `fa033021c7800716bbf725c803d5b608bfe89363`.
- Les workflows `tests` et `release` (test de publication **à blanc** en PR) étaient verts sur le dernier commit de l'étape 4 avant sa fusion.
- Recette indépendante de l'étape 4 sur `192.168.2.15:8085` : `running / healthy`, API `/healthz` en v0.5.0. Les simulations SPF, couverture, trois échecs consécutifs, résolution et droits non administrateurs ont été validées. Les événements et programmations simulés ont ensuite été nettoyés par restauration d'une sauvegarde vérifiée.
- La production `192.168.2.15:8080` utilisait encore `ghcr.io/vinzgithub/posture-cockpit:0.4.1`, healthy. **Cela ne constitue pas encore une validation de la version intégrée complète.**

## Barrières de validation avant livraison

- [ ] **CI de la branche d'intégration** : Python 3.11, 3.12 et 3.13, lint Ruff, mypy, tests navigateur, Docker, migrations, retour arrière. Ne pas confondre `release` GitHub Actions sur PR avec une image réellement publiée.
- [ ] **Recette intégrée de bout en bout** à partir du commit exact destiné à la livraison : utiliser un NOUVEAU conteneur, projet Compose, port et volume SQLite, distincts de 8080, 8082, 8083, 8084 et 8085. Ne jamais utiliser le volume `posture-cockpit_posture-cockpit-data` de production.
- [ ] Configurer `POSTURE_COCKPIT_SCHEDULER=off` et `POSTURE_COCKPIT_INTERNAL_SCANS=off` avant le premier démarrage de cette recette : la configuration applicative v0.5.0 active l'ordonnanceur par défaut si elle est absente.
- [ ] Rejouer la **migration sur copie cohérente et vérifiée** d'une base v0.4.1 ; vérifier le schéma 5, la conservation des comptes, scans et clés de session, et l'archive de sauvegarde complète générée avant migration.
- [ ] Vérifier le **retour vers v0.4.1** sur un volume de recette isolé, par restauration de l'archive pré-migration : l'image 0.4.1 ne doit jamais ouvrir directement la base en schéma 5.
- [ ] Revalider avec la version intégrée les vues de comparaison, les planifications (simulateur, DST, mode scheduler off), événements, historique, permissions des périmètres internes, FR/EN et API de compatibilité.
- [ ] Vérifier les horodatages des scans et l'absence de données fictives datées dans le futur avant de figer la recette.
- [ ] Vérifier l'image finale AMD64 et ARM64, l'immuabilité de la version publiée, et la procédure de publication et d'annulation.
- [ ] Faire relire les notes de livraison et les consignes de migration / retour arrière par le propriétaire.

## Précautions de publication

1. Garder pour l'instant la documentation de **démarrage rapide public** dirigée vers l'image et le tag `v0.4.1` : la 0.5.0 n'a pas encore de release publiée.
2. Préparer une validation explicite avant toute fusion de la branche d'intégration vers `feat/v0.5.0`, puis une **seconde validation explicite distincte** avant de modifier `main`, d'ajouter un tag, de publier une release ou d'actualiser la production.
3. Avant la mise à niveau de la production : capture/restauration testée des fichiers et des données, export externe de l'archive pré-migration, contrôle d'espace libre, fenêtre de maintenance, annonce de la désactivation ou activation contrôlée de l'ordonnanceur.
4. Après publication : les procédures d'installation publique pourront alors être actualisées pour `v0.5.0` (pas avant).

## Hors périmètre v0.5.0

Les libellés plus lisibles pour les identifiants techniques tels que `mail.spf` sont **reportés à une version ultérieure**, à la demande du mainteneur.

**Ce document n'autorise à lui seul aucun déploiement et ne remplace pas les essais de la version intégrée finale.**

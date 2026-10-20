# Événements et alertes — Posture Cockpit v0.5.0

> Fonctionnalité publiée en `v0.5.0`, sans effet sur les installations
> encore en v0.4.1. Toute migration de production nécessite une validation
> distincte. Aucun e-mail ni notification externe n'est envoyé.

## Ce que signifie un événement

L'onglet **Événements** signale les changements observés par les analyses complètes
et les revérifications. Un événement est **ouvert** tant qu'une observation concluante
n'a pas établi sa résolution. Les analyses sans mesures suffisantes ne ferment
**jamais** artificiellement une alerte de sécurité.

- **Sécurité** : un contrôle passe de conforme à « À améliorer » ou « Critique »,
  ou s'aggrave. Une correction confirmée résout l'événement. Le passage de
  « Critique » à « À améliorer » baisse sa gravité, sans le résoudre.
- **Score** : une baisse d'au moins **10 points**, uniquement si le comparateur
  historique estime les scores comparables. Une dégradation déjà expliquée par
  un nouveau contrôle défaillant ne crée pas une deuxième alerte de score.
  L'alerte reste ouverte jusqu'au retour au score de référence.
- **Mesure** : le taux de couverture passe sous 90 %. Il s'agit d'une perte de
  capacité d'observation, **pas** d'une vulnérabilité confirmée.
- **Technique** : trois échecs consécutifs d'analyses programmées ouvrent un
  incident unique, résolu lors d'une exécution programmée réussie.

La première analyse d'un domaine n'établit pas de changement : elle ne génère
pas d'événement de régression. Les états hérités, les générations de contrôles
différentes et les ensembles de contrôles incompatibles ne sont pas comparés.
Les résultats `blocked`, `error` et `na` ne prouvent ni une nouvelle faille
ni une correction.

## Consulter et filtrer

Ouvrir **Événements** dans la navigation. Filtrer par **état**, **gravité**,
**catégorie** ou nom exact du **domaine**. Les événements les plus récemment mis
à jour apparaissent en premier (100 par page actuellement, sans pagination).
Cliquer sur un domaine ouvre sa fiche technique.

Les administrateurs voient les événements des domaines Internet et des
périmètres internes. Les autres utilisateurs ne voient que les domaines Internet,
et aucun incident global d'administration.

Le nombre à côté de « Événements » indique les événements modifiés depuis
**votre** dernière consultation enregistrée. Cliquer sur **Marquer comme
consultés** met à jour votre repère personnel, **sans résoudre** les incidents.
La modification est protégée par authentification et CSRF.

## Conception et garanties

Le schéma SQLite 5 existant contient `events` et `users.events_seen_at` :
aucune migration supplémentaire. La création des observations immuables
`scan_states` et la mise à jour des événements sont dans une même transaction.
Le traitement est déterministe, idempotent et utilise l'unicité de l'événement
ouvert par domaine/type/sujet. Les valeurs historiques et scores enregistrés ne
sont jamais recalculés pour produire une alerte.

## Recette intégrée — 19 octobre 2026

Sur le conteneur de recette intégré **8086** (distinct de la production), deux analyses du domaine fictif `menuiserie-dupont.example` ont conservé un score de **57/100**, sans faux événement. La dégradation contrôlée du seul contrôle `mail.spf` a provoqué une baisse à **48/100** et ouvert un événement de sécurité **`open` / `critical`**. Le rétablissement du contrôle a ramené le score à **57/100** et l'événement à **`resolved` / `info`**.

Le bouton **« Marquer comme consultés »** a supprimé le badge de nouveautés tout en conservant l'incident résolu dans l'historique. Des captures de recette ont confirmé les états successifs. Ce test porte sur des observations **fictives et simulées**, sans panne réelle d'un service Internet.

Les tests d'étape 4 réalisés antérieurement sur le port isolé **8085** ont également couvert la perte de couverture, trois échecs d'analyses programmées et les droits des utilisateurs sur les périmètres internes. Les tests CI de la PR #26 étaient verts sur son **précédent commit** (`81a1b18...`, 9 jobs), et doivent être recontrôlés après toute mise à jour documentaire. Dossier de preuves : `docs/developer/RELEASE_V050.fr.md`.

## Recette et livraison

Vérifier les suites Python (3.11, 3.12, 3.13), Ruff, mypy, Docker, navigateur,
migrations et rollback sur la PR. Tester séparément une nouvelle dégradation,
une correction, les résultats non concluants, les échecs programmés, le bouton
« Marquer comme consultés » et les droits sur périmètres internes.

La recette Docker a utilisé un projet et un volume SQLite distincts de la production.
L'étape 4 a été validée en recette et fusionnée dans `feat/v0.5.0` via la PR #25.
La PR #27, le tag, la GitHub Release et les images GHCR ont été validés.
Cela ne constitue pas un accord pour déployer sur une instance existante :
suivre `docs/developer/RELEASE_V050.fr.md` et demander l'autorisation
spécifique du propriétaire avant toute migration.

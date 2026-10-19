# Événements et alertes — Posture Cockpit v0.5.0

> Fonctionnalité intégrée à la branche de développement `feat/v0.5.0`, mais non
> publiée. La production v0.4.1 ne doit pas être remplacée avant la validation
> complète de l'intégration. Aucun e-mail ni notification externe n'est envoyé.

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

## Recette et livraison

Vérifier les suites Python (3.11, 3.12, 3.13), Ruff, mypy, Docker, navigateur,
migrations et rollback sur la PR. Tester séparément une nouvelle dégradation,
une correction, les résultats non concluants, les échecs programmés, le bouton
« Marquer comme consultés » et les droits sur périmètres internes.

La recette Docker a utilisé un projet et un volume SQLite distincts de la production.
L'étape 4 a été validée en recette et fusionnée dans `feat/v0.5.0` via la PR #25.
L'intégration finale de la version reste à valider séparément, selon
`docs/developer/RELEASE_V050.fr.md`. Aucun merge dans `main`, tag, release ou
déploiement en production sans accord explicite du propriétaire.

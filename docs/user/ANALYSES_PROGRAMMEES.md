# Analyses programmées — Posture Cockpit v0.5.0 (recette)

> Cette fonction est en cours de recette. Ne pas activer dans l'installation
> de production v0.4.1. La branche de développement est `v050/etape-3`.

## Activation et sécurité

L'ordonnanceur est configuré par `POSTURE_COCKPIT_SCHEDULER=on|off`.
Dans un environnement de recette, définir explicitement
`POSTURE_COCKPIT_SCHEDULER=off` jusqu'à la validation des simulations.
Seul un administrateur ayant confirmé récemment son mot de passe peut
créer, suspendre, modifier ou supprimer une programmation dans la
page **Détails** d'un domaine. Chaque changement est journalisé.

Les autres utilisateurs peuvent consulter la programmation d'un domaine
auquel ils ont accès, mais pas la modifier. La page Administration indique
l'état de l'ordonnanceur, les prochains départs et les exécutions non terminées
correctement.

## Exécutions

Les fréquences proposées sont quotidienne, hebdomadaire et mensuelle,
en heure locale de l'instance. Les jours inexistants de fin de mois sont
ramenés au dernier jour du mois. Le changement d'heure est pris en compte
et une dispersion déterministe de dix minutes au maximum répartit les
départs.

Une analyse programmée conserve une provenance `schedule`, un état
historique et une ligne d'exécution. Les réservations s'appuient sur SQLite,
une clé unique par domaine et échéance, et un jeton à bail. Lors d'un arrêt
ou d'un échec, une exécution peut être marquée interrompue, échouée, manquée
ou ignorée. Les résultats sont enregistrés uniquement si le jeton de
réservation est encore valide.

L'ordonnanceur doit laisser de la capacité aux analyses demandées
manuellement, appliquer ses quotas et conserver les politiques réseau
applicables aux domaines Internet et internes.

## Recette avant fusion

Vérifier la suite de tests, les cas d'accès non administrateur/CSRF,
les conflits entre deux processus, les changements d'heure et les
redémarrages en cours d'analyse. La recette Docker doit utiliser un
**projet et un volume distincts**, jamais le volume de production.
Ne pas fusionner ni déployer sans autorisation du propriétaire.

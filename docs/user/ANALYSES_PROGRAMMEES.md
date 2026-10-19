# Analyses programmées — Posture Cockpit v0.5.0

> Cette fonction est intégrée dans `feat/v0.5.0`, mais la version n'est pas
> publiée. Ne pas l'activer sur la production v0.4.1 avant validation de
> l'intégration et de la procédure de migration.

## Activation et sécurité

L'ordonnanceur est configuré par `POSTURE_COCKPIT_SCHEDULER=on|off`.
Dans le démarrage normal de l'application v0.5.0, la valeur par défaut est `on`.
Dans un environnement de recette ou lors de la première migration, fixer
explicitement `POSTURE_COCKPIT_SCHEDULER=off` jusqu'à la validation des simulations.
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

## Recette et intégration

Les tests automatisés portent sur les droits d'administration et le CSRF,
les conflits entre deux processus, les changements d'heure et les
redémarrages en cours d'analyse. La recette isolée de l'étape 3 a été validée,
puis fusionnée dans `feat/v0.5.0` via la PR #24. La recette de l'étape 4
a ensuite validé l'incident créé après trois échecs et résolu après une
réussite simulée. Aucune de ces simulations n'a déclenché d'analyse réseau.

Avant toute publication, valider la version intégrée dans un **projet et
un volume distincts**, jamais sur le volume de production, et suivre
`docs/developer/RELEASE_V050.fr.md`. Ne pas fusionner dans `main`,
publier ni déployer sans autorisation du propriétaire.

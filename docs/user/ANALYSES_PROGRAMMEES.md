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

## Validation intégrée de l'ordonnanceur — 19 octobre 2026

La recette intégrée **8086**, construite depuis le commit applicatif `fa033021...`, conserve `POSTURE_COCKPIT_SCHEDULER=off`. Une programmation quotidienne à **05:00** y a été enregistrée mais maintenue inactive : Administration a confirmé « ordonnanceur désactivé », aucune échéance active et aucune exécution en erreur.

Un essai distinct a été réalisé dans le conteneur éphémère `pc-v050-scheduler-execution-test`, volume Docker `pc-v050-scheduler-test-data`, **aucun port publié et réseau `none`**. Sur le seul conteneur de cet essai, l'ordonnanceur était activé. Après une analyse fictive manuelle initiale (score 57), une programmation quotidienne active avec échéance échue a été créée. Après les **120 secondes de temporisation au démarrage** :

- seconde analyse automatiquement enregistrée, **score 57/100, origine `via=schedule`** ;
- journal `schedule_runs` : créneau `2026-10-19T22:27`, état **`done`**, **1 tentative** ;
- conteneur arrêté puis supprimé ; volume de données conservé comme preuve.

Le test valide l'exécution réelle par le processus d'ordonnancement avec des **réponses fictives intégrées** et sans connexion Internet. Il ne valide pas les résultats d'un balayage d'un site réel. L'ordonnanceur de 8086 n'a pas été activé.

Pour une future mise à jour de production, configurer explicitement `POSTURE_COCKPIT_SCHEDULER=off` lors du premier démarrage, puis décider séparément de l'activation en fonction des domaines, des quotas et des horaires. La version v0.5.0 n'est pas encore publiée.

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

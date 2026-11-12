# Contrôle SMTP STARTTLS (v0.7.0)

🇬🇧 [English version](SMTP_STARTTLS.md)

Le contrôle **« Chiffrement SMTP des serveurs de réception (STARTTLS) »** (`mail.smtp_starttls`) vérifie que les serveurs de messagerie qui reçoivent le courrier du domaine (ses MX) proposent **STARTTLS** sur le port 25 et présentent un **certificat valide pour leur nom**. C'est ce qu'un expéditeur exige avant de livrer quand le domaine impose le chiffrement avec **MTA-STS** en mode `enforce`.

Ce contrôle est **facultatif et désactivé par défaut**. C'est le seul contrôle qui se connecte aux serveurs de messagerie : tous les autres lisent le DNS, HTTPS et HTTP.

## Ce qu'il fait

Quand la sonde est active, pour chaque analyse :

1. il lit les MX publiés, comme le contrôle « Serveurs de messagerie » ;
2. il en garde **8 au plus**, par préférence ; ceux au-delà sont signalés dans les notes ;
3. il ouvre **16 connexions au plus** (8 en même temps), en alternant IPv4 et IPv6 : une adresse de chaque MX avant une deuxième de l'un d'eux ;
4. sur chaque connexion : il attend l'accueil `220`, envoie `EHLO <votre nom>`, demande `STARTTLS`, négocie TLS 1.2 ou 1.3 et vérifie le certificat (chaîne de confiance, nom du MX publié, dates) ;
5. **il s'arrête là** : aucun `MAIL FROM`, aucun destinataire, aucun message, puis `QUIT`.

L'ensemble tient en `min(12 s, POSTURE_COCKPIT_CHECK_TIMEOUT − 2 s)`, soit 12 s avec le réglage par défaut (15 s). Ce qui a été observé avant cette échéance est conservé.

Les connexions suivent la **règle de sortie** des analyses : uniquement des adresses publiques, uniquement le port 25, jamais dans un périmètre interne (le contrôle y est « non applicable »).

## L'activer

Dans le fichier `.env` (voir [INSTALLATION.fr.md](INSTALLATION.fr.md#réglages)) :

```bash
POSTURE_COCKPIT_SMTP_PROBE=on
POSTURE_COCKPIT_SMTP_EHLO_NAME=sonde.mon-domaine.fr
```

puis `docker compose up -d`.

- **Le nom EHLO est obligatoire** quand la sonde est active ; il n'a pas de valeur par défaut. C'est un nom DNS complet (au moins deux libellés, en ASCII, la forme `xn--` pour un nom internationalisé), sans espace ni caractère de contrôle. Choisissez un nom **que vous contrôlez**, idéalement avec une adresse et un enregistrement inverse cohérents : c'est par ce nom que la sonde se présente aux serveurs contactés.
- Une valeur invalide **empêche le démarrage**, avec la variable et la raison dans le journal. Même règle pour `POSTURE_COCKPIT_SMTP_PROBE` (seulement `on` ou `off`) et pour `POSTURE_COCKPIT_CHECK_TIMEOUT`, qui doit rester supérieur à 2 s quand la sonde est active.
- **Le port 25 sortant doit être ouvert** vers Internet. Beaucoup de fournisseurs d'accès et d'hébergeurs le bloquent. Sans lui, chaque analyse finit en « non évalué » pour ce contrôle (« port 25 inaccessible ou délai dépassé »), ce qui fait baisser la couverture : laissez alors la sonde désactivée.

Désactivée, la sonde ne contacte rien. Le contrôle est « non applicable », avec le message « Contrôle SMTP non effectué : sonde désactivée sur cette instance ». Il ne compte pas dans la note.

## Ce qu'il conclut

| Résultat | Quand |
|---|---|
| Conforme | Chaque adresse publiée de chaque MX propose STARTTLS avec un certificat valide. Ou bien au moins une adresse de chaque MX a été vérifiée, et ce qui n'a pas pu l'être est indiqué dans les notes |
| À améliorer | Certificat refusé sans politique MTA-STS `enforce` en vigueur ; certificat valide mais expirant dans 20 jours ou moins |
| Critique | Un serveur ne propose pas STARTTLS ; certificat refusé alors qu'une politique `enforce` est en vigueur (les expéditeurs qui l'appliquent ne livrent plus à ce serveur) |
| Non évalué | Un MX n'a rien donné de concluant : port 25 bloqué, délai, refus SMTP, `STARTTLS` refusé, négociation TLS inaboutie, capacités ESMTP masquées par un équipement intermédiaire, erreur DNS. **Ce n'est jamais présenté comme un défaut du serveur** |
| Non applicable | Sonde désactivée, périmètre interne, ou domaine sans courrier entrant (pas de MX, ou MX nul) |

Le contrôle pèse **5** dans la note (catégorie Messagerie ; voir [SCORING.fr.md](SCORING.fr.md#4-les-poids)). Un défaut prouvé n'est jamais masqué par une mesure manquante ailleurs.

## Préparation au mode `enforce` de MTA-STS

À côté du résultat, la page de détail, le rapport PDF et l'API (`mail_enforce_readiness`) donnent un indicateur distinct :

| État | Sens |
|---|---|
| Prêt selon les mesures réalisées depuis cette instance | Toutes les adresses publiées vérifiées, politique MTA-STS valide en mode `testing` couvrant chaque MX |
| Compatible avec la politique enforce en vigueur | Même chose, la politique étant déjà en `enforce` |
| À corriger | STARTTLS absent, certificat refusé, ou MX non couvert par la politique |
| Impossible à confirmer | Sonde désactivée, mesure incomplète, politique absente, en mode `none`, invalide ou illisible, MX qui est un alias (CNAME) ; toutes les causes sont listées |
| Sans objet | Pas de courrier entrant |

« Prêt » n'est **pas une garantie de livraison** : le port 25 joint depuis votre instance ne prouve pas que les expéditeurs d'Internet le joignent.

## Limites

- **Point de vue de l'instance.** Le résultat dépend du réseau qui héberge Posture Cockpit (filtrage, routage IPv6, inspection ESMTP). Une adresse non joignable est « non évaluée », pas en défaut.
- **Échantillon.** 8 MX et 16 connexions au plus par analyse ; ce qui n'a pas été testé est listé, et la préparation reste alors « impossible à confirmer ».
- **Pas de verdict sur les versions de TLS** en 0.7.0 : un refus de version ou une alerte TLS laisse le serveur « non évalué ».
- **Ni sécurité active, ni test de relais.** Aucun message n'est envoyé ; la sonde ne cherche pas de vulnérabilité.
- **Preuves bornées.** Les observations enregistrées tiennent dans 64 Kio ; les listes de MX et de motifs MTA-STS des contrôles « Serveurs de messagerie » et « MTA-STS » gardent 16 éléments (les plus significatifs d'abord), avec le nombre exact de ceux qui sont omis.
- **Charge.** Chaque analyse peut ouvrir jusqu'à 16 connexions SMTP ; les analyses programmées et les revérifications aussi. Les quotas d'analyses s'appliquent comme d'habitude.

## Historique et comparaisons

Activer ou désactiver la sonde change **ce qui est mesuré**, pas le domaine. Deux analyses dont la sonde était dans des états différents ne sont donc **pas comparées** : pas d'écart de note, pas d'événement. L'historique et Mission Control l'indiquent (« portée de mesure différente (sonde SMTP activée ou désactivée) »). Cette portée est lue dans le résultat enregistré de chaque analyse, jamais dans la configuration actuelle. L'API la donne dans `smtp_probe.scope` : `on`, `off`, `internal`, ou `absent` pour une analyse antérieure à la 0.7.0 (voir [HOME_ASSISTANT.fr.md](HOME_ASSISTANT.fr.md#ajouts-de-lapi-en-07)).

Les analyses faites en v0.6.x ne sont pas comparées non plus à celles de la v0.7.0, qui jugent avec d'autres règles (génération 5 ; voir [SCORING.fr.md](SCORING.fr.md#version-07--contrôle-smtp-et-génération-5)).

Références : RFC 3207 (STARTTLS), RFC 8461 (MTA-STS), RFC 7505 (MX nul), RFC 5321.

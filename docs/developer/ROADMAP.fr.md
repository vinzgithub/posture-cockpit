# Posture Cockpit — feuille de route de développement

🇬🇧 [English version](ROADMAP.md)

> **Document de planification — 14 octobre 2026.** Les fonctionnalités futures ci-dessous sont des **objectifs**, pas des fonctionnalités livrées, des engagements de dates ou des attestations de conformité. Chaque livraison reste soumise aux tests, à la recette et à l'accord du responsable du projet.

## Vision et publics visés

Faire évoluer Posture Cockpit d'un auditeur de posture de domaines **auto-hébergé** vers un outil de **pilotage continu de l'exposition DNS, Web, PKI et messagerie**, utilisable par :

- particuliers, associations, TPE/PME et prestataires ;
- collectivités, établissements et administrations publiques ;
- grandes entreprises, groupes multi-entités et équipes RSSI/SOC.

Le produit doit rester utilisable sans IA ni service cloud tiers. Sa valeur principale est la **mesure reproductible** : preuves, provenance, limites, couverture, historique et remédiations vérifiables. Une réponse inaccessible ou une mesure impossible ne doit jamais devenir « conforme ».

## Socle existant et travaux en cours

- **v0.2.0 livrée** : analyse passive, interface FR/EN, contrôle d'accès et 2FA, API, rapports, couverture du score, historique de scans stocké, périmètres internes contrôlés, protections SSRF/egress, Docker.
- **v0.3.0 en préparation** : les PR [#4](../../pull/4), [#5](../../pull/5), [#6](../../pull/6) et [#7](../../pull/7) sont intégrées à `main` ; restent les vérifications fonctionnelles, les derniers écarts HTTPS / TLS-RPT / DKIM et la recette de release. La [PR #10](../../pull/10) traite le faux verdict HTTPS et n'est pas fusionnée à la date de ce document.
- **SMTP/STARTTLS développé en avance, non livré** : [PR #8](../../pull/8) (socle) et [PR #9](../../pull/9) (interprétation des preuves et diagnostics) sont en brouillon. Leur validation par MX, IP, famille réseau et point de mesure doit être achevée avant leur livraison.

## Jalons recommandés

| Jalon | Objectif | Critères avant sortie |
|---|---|---|
| **v0.3.0 — fiabilité** | Finaliser HTTPS/redirections, TLS-RPT, DKIM, conseil MTA-STS, puis consolider historique/PDF, DMARC RFC 9989, horaires, interface et cookies déjà développés | Tests CI, revue sécurité, comparaison des huit domaines de recette, historique et PDF fidèles, retour arrière testé |
| **v0.4.0 — SMTP/STARTTLS** | Finaliser les PR #8/#9 : opt-in administrateur, port 25 strictement limité aux MX autorisés, EHLO, STARTTLS, certificat et erreurs explicites | Sonde réelle autorisée + SMTP mock ; aucun SMTP intrusif ; aucun faux « conforme » ; couverture par MX et adresse |
| **v0.4.x / v0.5.0 — mesure et profils** | Suites/versions TLS SMTP mesurables, profils **Web / Messagerie / Mixte** avec scoring adapté et comparaison des anciennes notes | Contrôles sans extrapolation, tests de non-régression, compatibilité API et PDF, décision validée sur les poids |
| **v0.5.x et suivants — exploitation continue** | Planification des analyses, alertes sur changements, comparaison temporelle, tableaux de bord de portefeuille | Anti-bruit, cadence et quotas, tâches résilientes, historique immutable et preuve de l'origine de mesure |
| **v0.6+ — périmètres élargis** | DANE/DNSSEC, IPv6 mesurable, RPKI avec source fiable, exports/imports tracés, agents distants à sécurité bornée | Revue de sécurité propre à chaque lot, provenance et erreurs explicites, aucun scan hors autorisation |
| **Piste grands comptes / secteur public, après validation du besoin** | Multi-entités, SSO, rôles avancés, rapports RSSI, capacité volumétrique et exploitation renforcée | Pilotes avec utilisateurs, isolation des droits, critères de performances, documentation et exploitation vérifiables |

Le séquencement est **indicatif**, sans calendrier fixé. Un besoin démontré par des pilotes peut modifier les priorités, mais pas les garanties de sécurité.

## Évolutions pour les administrations et grandes entreprises

Les besoins suivants constituent des **épics à étudier et découper en PR**, pas des capacités actuelles.

### E1 — Portefeuille de domaines et responsabilité

Inventaire des domaines et sous-domaines **explicitement autorisés** ; regroupement par organisme, direction, filiale, service et environnement ; propriétaire technique/fonctionnel ; dates de dernière observation et périmètre de mesure. Recherche, filtrage, tags et détection des domaines orphelins avec validation humaine.

**Recette :** un domaine ne peut être scanné sans autorisation ni être attribué à une entité sans traçabilité ; la couverture du portefeuille n'est pas confondue avec le score de sécurité.

### E2 — Gestion multi-entités et habilitations

Rôles administrateur de plateforme, responsable d'entité, auditeur et lecteur ; permissions minimales par domaine et périmètre ; séparation des vues, historiques, PDF, API, export et actions. SSO OIDC/SAML, MFA selon politique, révocation des sessions et compte d'administration de secours.

**Recette :** tests d'isolation inter-entités (dont IDOR), de révocation et d'audit ; aucune fuite de constats internes dans les rapports ou les API. La gestion multi-entités n'est **pas** équivalente aux simples comptes déjà présents.

### E3 — Surveillance continue et alertes

Planification contrôlée, exécution asynchrone et file de travaux ; alertes sur expiration de certificat, dégradation DNS/MTA-STS/DMARC/STARTTLS, baisse de couverture et changement de configuration ; destinations e-mail ou webhook à configurer, dédoublonnage et acquittement.

**Recette :** pas d'alerte « panne du domaine » sur un échec propre à la sonde ; quotas et plafonds réseau conservés, absence de doublons à chaque scan.

### E4 — Tableaux de bord RSSI et rapports consolidés

Indicateurs par entité, évolution dans le temps, exceptions acceptées avec justification et échéance, priorités de remédiation, export PDF/CSV/JSON versionné, preuve du contrôle et origine du point de mesure. Connecteurs SIEM/ITSM **optionnels**.

**Recette :** chaque indicateur est retraçable jusqu'aux constats, avec couverture et limites ; pas de score global trompeur ni d'affirmation de « conformité réglementaire » sans référentiel et audit spécifiques.

### E5 — Capacité industrielle et exploitation

Mesurer la charge sur des jeux de **100 puis 1 000 domaines** ; file de scans, concurrence, reprise après incident, sauvegarde/restauration, migrations, supervision et journaux. Évaluer l'évolution éventuelle de SQLite vers PostgreSQL sur la base de mesures, **pas par principe**. Livraison auto-hébergée, hors ligne lorsque possible, images durcies, SBOM, gestion des vulnérabilités, règles de sauvegarde et politique de rétention.

**Recette :** objectifs de temps, mémoire et disponibilité définis puis mesurés avant promesse de capacité ; restauration et mise à jour reproductibles.

### E6 — Points de mesure distants

Agents optionnels pour des réseaux autorisés, suivant l'[étude existante](REMOTE_AGENT.fr.md). Authentification forte, règles de sortie locales non extensibles par le serveur central, tâches bornées et résultats authentifiés, étiquetés par sonde et réseau.

**Recette :** tests contre l'élargissement de périmètre, les agents compromis/hors ligne et les données manipulées ; aucune exécution de commandes arbitraires.

### E7 — Accessibilité, confidentialité et gouvernance

Étudier, en fonction des clients et du contexte réel : accessibilité **RGAA/WCAG**, RGPD et conservation des données, exigences PSSI, hébergement/souveraineté, auditabilité, traçabilité d'administration, documentation d'exploitation, politique de support, conditions contractuelles et d'achats publics.

**Précaution :** la mention de références ANSSI, RFC ou RGAA ne vaut ni qualification ANSSI, ni homologation, ni certification, ni preuve de conformité juridique. Les exigences applicables sont à établir au cas par cas.

### E8 — Assistance IA facultative, sans verdict inventé

À étudier **après** stabilisation des preuves techniques : expliquer un constat dans un langage adapté à l'administrateur ou au RSSI, proposer une remédiation, préparer un résumé exécutif, comparer des tendances. L'IA ne doit **jamais être l'autorité du verdict** : chaque proposition reste rattachée aux constats du moteur, contrôlable et soumise à validation humaine.

**Recette :** fonction désactivée par défaut, pas de transfert externe de secrets ou de données internes sans choix explicite, possibilité d'un modèle local, journalisation appropriée et distinction stricte entre observation, hypothèse et recommandation.

## Principes non négociables

1. **Sécurité avant richesse fonctionnelle** : SSRF/egress, autorisations, budgets réseau, opt-in sur les contrôles actifs limités, protection des secrets et tests de non-régression.
2. **Pas de faux positif de conformité** : distinguer vérifié, observé indirectement, non évalué et non applicable ; score **et couverture** toujours visibles.
3. **Bilingue dès l'origine** : interface, rapports, états et documentation FR/EN, y compris sur mobile.
4. **Modularité** : conserver le noyau adapté aux usages individuels/PME ; capacités grands comptes et IA **facultatives** et isolées.
5. **Livraison maîtrisée** : PR limitées, CI `test`/`docker` vertes, revue de sécurité, recette sur instance isolée, sauvegarde et procédure de retour arrière ; aucune fusion ni production sans accord explicite.
6. **Licence et mise sur le marché** : la licence publique actuelle est [PolyForm Noncommercial 1.0.0](../../LICENSE). Étudier séparément les conditions d'utilisation commerciale, le support et la distribution avant toute offre professionnelle.

## Portes de décision avant une offre « administrations / grands comptes »

- Rencontrer des RSSI, administrateurs et exploitants de structures de tailles différentes, obtenir des scénarios réels et définir les **3 à 5** besoins les plus demandés.
- Tester un pilote sur un portefeuille autorisé, avec critères convenus (exactitude, couverture, disponibilité, contrôle d'accès, charge et restitution).
- Confronter le produit aux alternatives existantes ; définir la différenciation mesurable et le modèle de support/licence.
- N'annoncer « prêt pour grands comptes » qu'après sécurité, maintenabilité, exploitation et retour de pilote documentés.

**Référence de périmètre :** cahier des charges consolidé v0.3.0 du 13/10/2026 ; ce document le prolonge sans remplacer ses critères de recette.

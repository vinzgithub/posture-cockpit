# Feuille de route — Posture Cockpit

🇬🇧 [English version](ROADMAP.md)

> **Pistes pour les futures versions, sans engagement de livraison.** Cette roadmap reste soumise aux tests utilisateurs et aux revues techniques. **Mission Control n'est pas prévu dans la v0.4.1, et aucun numéro de version (y compris v0.5.0) ne lui est attribué.**

## Court terme — démontrer la valeur et la fiabilité

- Comparer les constats à des outils indépendants sur divers domaines audités avec autorisation. Documenter faux positifs, faux négatifs, couverture diagnostique et divergences.
- Faire tester l'outil à des personnes qui ne connaissent pas le projet : comprendre une anomalie, effectuer une correction sûre, vérifier son effet et lire le rapport PDF.
- Corriger les problèmes constatés avant de multiplier les contrôles.
- Séparer strictement preuves réellement mesurées, observations inconnues ou bloquées et hypothèses de correction.

## Version ultérieure possible — surveillance continue

- Audits périodiques activés volontairement et détection des changements.
- Alertes exploitables sur les régressions de sécurité et l'expiration des certificats, avec limitation des notifications.
- Historique daté des changements mesurés, y compris les incertitudes et les limites des mesures.

## Concept pour une version future — dashboard interactif « Mission Control »

**Objectif :** un cockpit de remédiation vérifiable et interactif, pas seulement des graphiques de score.

1. **Graphe interactif des dépendances :** explorer les contrôles racines et dépendants ainsi que l'effet des observations HTTPS/certificat bloquées ou indéterminées.
2. **Machine à remonter le temps :** comparer deux audits datés et leurs preuves techniques avant/après ; distinguer les changements réels des différences de mesure.
3. **Simulateur de corrections :** sélectionner des remédiations et estimer le gain sur la note et la couverture avec le véritable moteur de notation, ses plafonds et ses dépendances. Afficher des intervalles lorsque les gains sont provisoires.
4. **Parcours de correction vérifiable :** indiquer quoi modifier et où, préparer les valeurs à copier ou le message au prestataire, relancer les contrôles puis comparer prévision et résultat observé.
5. **Pilotage des dérives :** après la mise en place des audits périodiques, afficher les régressions, alertes de certificat et changements importants dans un fil d'événements priorisé.
6. **Ergonomie cohérente et accessible :** ordinateur/mobile, navigation clavier et lecteur d'écran, français/anglais, horodatage et provenance des preuves.

### Garde-fous et conditions de validation

- Pas de tests intrusifs ni de modifications automatiques des DNS/serveurs ; préserver le filtrage réseau et les contrôles passifs actuels.
- Ne jamais laisser une IA générative inventer des constats, mesures ou scores non explicables ; distinguer les éventuelles explications IA des preuves mesurées.
- Respecter les états bloqué/indéterminé, la couverture, les dépendances et le comportement stable de la v0.4.x.
- Développer sur une branche dédiée, avec tests automatisés et vraie recette utilisateur.
- Avant livraison : un testeur doit pouvoir terminer une correction seul ; les simulations doivent être traçables au moteur ; mesure, simulation et correction vérifiée doivent rester distinctes ; les mesures partielles doivent rester correctes ; l'interface doit fonctionner sur mobile et en FR/EN.

*Le calendrier, le périmètre et la version cible dépendront des retours utilisateurs et des vérifications techniques.*

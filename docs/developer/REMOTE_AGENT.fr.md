# Étude : un agent Docker distant pour les audits internes

🇬🇧 [English version](REMOTE_AGENT.md)

Statut : **étude, non développée.** La version 0.2.0 prépare le terrain sans ajouter d'agent ; ce document dit pourquoi, comment il pourrait fonctionner et ce qu'il coûterait.

## 1. Le besoin

Aujourd'hui, un périmètre interne n'est analysable que si l'instance centrale **joint elle-même** le réseau interne : elle y est installée, ou une route, un VPN ou une règle de pare-feu lui ouvre ces réseaux. Pour auditer plusieurs sites (siège, agences, un client), il faudrait soit une instance par site, soit ouvrir des flux entrants vers chacun depuis l'instance centrale. Les deux sont lourds, et le second élargit la surface d'attaque des réseaux audités.

Un **agent** est un petit conteneur déposé dans chaque réseau interne. Il ne fait que des analyses, sur ordre de l'instance centrale, et lui renvoie les résultats. Les flux vont de l'agent vers l'instance (sortants pour le réseau audité), jamais l'inverse.

```
  réseau interne A                         instance centrale
 ┌──────────────────────┐   HTTPS sortant  ┌────────────────────────────┐
 │ agent  ── analyses ─► │ ───────────────► │ API agents ─► scans, plan, │
 │ (règle locale :      │ ◄─ travaux ───── │ PDF, historique, audit     │
 │  réseaux de A)       │                  └────────────────────────────┘
 └──────────────────────┘
```

## 2. Pourquoi le code actuel s'y prête

- Le **moteur est indépendant du web** (`core/`) : un agent peut lancer `engine.scan` sans serveur web, comme le fait déjà la ligne de commande.
- La **règle de sortie** est un objet (`EgressPolicy`) appliqué par `LiveNetwork` : l'agent construit la sienne à partir de sa propre configuration.
- Un **périmètre** est une donnée (réseaux, DNS, ports, AC) et non une configuration du serveur.
- Les **résultats sont sérialisables** : `Finding.outcome_json()` et `Finding.from_stored()` sont déjà le format de la base.
- Le **scanner** choisit le réseau selon le périmètre (`Scanner.network_for`) : c'est le point où l'instance déciderait d'analyser elle-même ou de confier le travail à un agent.

## 3. Fonctionnement proposé

1. **Enrôlement.** Un administrateur crée un agent dans l'interface et reçoit un jeton à usage unique. L'agent l'échange contre une clé propre (ou un certificat client), stockée hachée côté instance, révocable.
2. **Travaux.** L'agent interroge l'instance à intervalle régulier (*long polling*, HTTPS sortant uniquement) : « un travail pour moi ? ». Un travail = un domaine, l'identifiant du périmètre, la liste des contrôles et une échéance.
3. **Analyse.** L'agent applique **sa propre règle de sortie**, définie localement (variables d'environnement de son conteneur). L'instance centrale ne peut pas l'élargir : si elle demande un domaine qui pointe hors des réseaux de l'agent, les contrôles sont « non évalués », exactement comme aujourd'hui.
4. **Résultats.** L'agent renvoie les `Finding` sérialisés, sa version et celle de chaque extension. L'instance les traite comme une **entrée non fiable** : identifiants de contrôles connus, états valides, tailles bornées, textes réduits à des clés de traduction (comme aujourd'hui), preuves (« evidence ») limitées en taille.
5. **Traçabilité.** Chaque travail confié, accepté, terminé ou expiré est inscrit au journal d'audit, avec l'agent concerné.

## 4. Sécurité

| Risque | Mesure |
|---|---|
| L'instance centrale est compromise et veut se servir des agents pour sonder les réseaux internes | La règle de sortie est locale à l'agent ; les contrôles restent passifs ; l'agent n'exécute aucun code reçu, seulement des contrôles déjà installés |
| Un agent est compromis et envoie de faux résultats | Clé révocable par agent ; résultats validés ; les analyses d'un agent sont marquées comme telles dans le PDF et l'historique |
| Le jeton d'enrôlement fuit | Usage unique, courte durée, lié à un périmètre |
| Interception | HTTPS avec vérification du certificat de l'instance (AC configurable côté agent), éventuellement mTLS |
| Exposition de l'agent | Aucun port en écoute ; conteneur en lecture seule, sans capacités, utilisateur non privilégié (comme l'image actuelle) |

## 5. Coût et difficultés

- **API et interface** : enrôlement, liste des agents, état (dernier contact, version), révocation ; file de travaux avec échéances.
- **Écarts de version** : un agent plus ancien que l'instance peut ne pas connaître un contrôle ; il doit le signaler (contrôle « non évalué » côté instance) plutôt que d'échouer.
- **Agents hors ligne** : les travaux expirent ; l'interface dit « en attente de l'agent » au lieu d'un faux résultat.
- **Tests** : un agent et une instance dans les tests, avec les serveurs locaux déjà disponibles (`tests/local_servers.py`).

Estimation : de l'ordre de la taille de la 0.2.0 (nouveau module `agent/`, routes `api/v1/agents`, deux tables, une page d'administration, la documentation), sans refonte de l'existant.

## 6. Recommandation

**Ne pas le développer maintenant.** La priorité est la consolidation : règle de sortie, notation, exactitude des contrôles. Ces fondations étaient aussi les prérequis d'un agent : elles sont posées. L'agent devient utile dès qu'il faut auditer plusieurs réseaux internes depuis une seule instance ; d'ici là, une instance installée dans le réseau interne, avec un périmètre, couvre le besoin.

Étapes proposées le moment venu :

1. une commande `posture-cockpit scan --perimeter <fichier>` qui produit le JSON d'une analyse interne (utile seule, et premier morceau de l'agent) ;
2. l'import de ce JSON dans l'instance (historique, plan, PDF) ;
3. l'enrôlement et la file de travaux.

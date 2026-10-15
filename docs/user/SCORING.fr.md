# Comment la note est calculée

🇬🇧 [English version](SCORING.md)

La note de Posture Cockpit résume une analyse passive. Elle ne remplace pas un audit : elle dit ce qui a pu être vérifié de l'extérieur, et dans quelle mesure. Cette page décrit les règles exactes, appliquées de la même façon sur le plan, la liste des domaines, l'API, le rapport PDF et l'historique.

## 1. Ce que devient chaque contrôle

| État | Sens | Dans la note |
|---|---|---|
| Conforme | Rien à faire | Tout son poids |
| À améliorer | Pas dangereux en soi, mais à renforcer | La moitié de son poids |
| Critique | À corriger | Rien |
| Non évalué | Le contrôle s'applique, mais n'a pas pu être fait : serveur muet, délai dépassé, destination refusée par la règle de l'analyse, version de TLS que la machine ne sait plus tester | Écarté de la note, **fait baisser la couverture** |
| Non applicable | Le contrôle ne concerne pas ce domaine : pas de site web, pas de courrier entrant, contrôle fait pour Internet dans un audit interne | Écarté |
| Information | Rien à juger (où arrive le courrier, clé DKIM introuvable sous les noms usuels) | Écarté |

La différence entre « non évalué » et « non applicable » est essentielle : un contrôle qui *aurait dû* répondre et n'a pas pu le faire est un trou dans l'évaluation, jamais une réussite.

## 2. Couverture

La **couverture** est le poids des contrôles évalués divisé par le poids des contrôles applicables (évalués + non évalués). Elle est affichée avec chaque note : « Couverture 92 % : 18 contrôles évalués sur 20 ».

## 3. Note et lettre

La note est la part du poids gagnée par les contrôles évalués, de 0 à 100. La lettre suit la note :

| Lettre | Note | Libellé |
|---|---|---|
| A | 85 et plus | Solide |
| B | 70 à 84 | Correct |
| C | 55 à 69 | À surveiller |
| D | 40 à 54 | Fragile |
| E | 25 à 39 | Exposé |
| F | moins de 25 | Critique |

Puis deux règles liées à la couverture :

- **sous 50 % de couverture : « Non évalué »**, sans note ni lettre. Trop peu a été vérifié pour juger le domaine ; les problèmes trouvés restent listés et à corriger ;
- **sous 90 % : évaluation partielle**. La note est donnée avec sa couverture, et la lettre ne peut pas dépasser **B** : un A affirme que le domaine a été vérifié, pas seulement que ce qui a pu l'être allait bien.

Les pourcentages de couverture sont arrondis à l'unité inférieure : 89,6 % s'affiche 89 %, jamais 90 %.

## 4. Les poids

Inchangés depuis la version 0.1.0.

| Contrôle | Domaine | Poids | Audit interne |
|---|---|---|---|
| Protection contre l'usurpation (DMARC) | Messagerie | 10 | non applicable |
| Certificat du site | TLS | 10 | oui |
| Expéditeurs autorisés (SPF) | Messagerie | 8 | non applicable |
| Passage automatique en HTTPS | Site web | 8 | oui |
| HTTPS obligatoire (HSTS) | Site web | 6 | oui |
| Versions de TLS | TLS | 5 | oui |
| Signature des e-mails (DKIM) | Messagerie | 4 | non applicable |
| Politique de sécurité du contenu (CSP) | Site web | 4 | oui |
| Serveurs de noms | DNS | 4 | non applicable |
| Signature DNSSEC | DNS | 4 | non applicable |
| Chiffrement imposé à la réception (MTA-STS) | Messagerie | 3 | non applicable |
| Clé du certificat | TLS | 3 | oui |
| Protection contre l'intégration (clickjacking) | Site web | 3 | oui |
| Types de fichiers respectés (nosniff) | Site web | 2 | oui |
| Versions des logiciels affichées | Site web | 2 | oui |
| Autorités de certification autorisées (CAA) | DNS | 2 | non applicable |
| Serveurs de messagerie (MX) | Messagerie | 1 | non applicable |
| Rapports de chiffrement (TLS-RPT) | Messagerie | 1 | non applicable |
| Adresse de provenance (Referrer-Policy) | Site web | 1 | oui |
| Contact sécurité (security.txt) | Site web | 1 | non applicable |

Le contrôle MX est une information tant que les serveurs de messagerie sont joignables ; il ne compte (« à améliorer ») que si l'un d'eux n'a pas d'adresse.

## 5. Le plan de corrections

Les contrôles critiques forment les **priorités**, les contrôles à améliorer les **améliorations**, chacun classé par effet sur la note puis par rapidité. Les points affichés sont cumulés : leur somme donne exactement la note visée. Quand le domaine n'est pas évalué, les tâches restent proposées mais sans points, puisqu'il n'y a pas de note de départ.

## 6. Ce qui a changé en 0.2.0, et pourquoi

| Avant (0.1.0) | Depuis (0.2.0) | Raison |
|---|---|---|
| Aucun contrôle évaluable : 100/100, A | « Non évalué » | Un domaine ne doit jamais paraître sûr parce que presque rien n'a pu être vérifié (anomalie reproduite lors de l'audit) |
| 19 contrôles en erreur et 1 conforme : 100/100, A | « Non évalué » (couverture 5 %) | Idem |
| Pas d'indication de ce qui a été réellement vérifié | Couverture affichée partout | Lire une note sans savoir sur quoi elle porte induit en erreur |
| A possible avec une partie seulement des contrôles | A seulement à partir de 90 % de couverture | Un A doit valoir pour le domaine, pas pour un échantillon |
| « Pas de site web », « pas de courrier » en information | « Non applicable » | Distinguer ce qui ne s'applique pas de ce qui informe |

Les poids et la formule de la note ne changent pas. Les analyses déjà enregistrées ont été recalculées avec ces règles lors de la mise à jour : leur note chiffrée ne change pas quand leur couverture atteint 50 % ; en dessous, elles deviennent « Non évalué » ; un A obtenu avec moins de 90 % de couverture devient B. Une copie de la base d'avant la mise à jour est conservée dans `backups/`.

Les corrections de contrôles de la 0.2.0 (DMARC, SPF, cadrage, CSP… voir le [CHANGELOG](../../CHANGELOG.md)) peuvent, elles, faire varier la note d'une nouvelle analyse par rapport à la précédente : c'est le diagnostic qui est devenu plus juste, pas le domaine qui a changé.

## 7. Ce qui a changé en 0.3.x, et pourquoi

Les poids, la formule de la note et les règles de couverture ne changent pas, et les analyses enregistrées ne sont pas recalculées. Ces verdicts ont changé en 0.3.2 ; ils peuvent faire varier la note de la prochaine analyse :

| Situation | 0.3.1 | 0.3.2 | Raison |
|---|---|---|---|
| DMARC `p=reject; pct=0` (ou tout `pct` inférieur à 100) | Conforme | À améliorer | La RFC 9989 a retiré `pct`, mais les messageries qui suivent encore la RFC 7489 n'appliquent la politique qu'à cette part des e-mails en échec |
| DMARC `pct=101`, `pct=abc` | Conforme | À améliorer (valeurs à corriger) | RFC 7489 §6.3 : un entier de 0 à 100 |
| `http://` renvoie vers un autre site, `https://domaine/` répond avec un certificat valide | Critique | Conforme | Envoyer les visiteurs vers un autre site est un choix ; le HTTPS du domaine fonctionne |
| Idem, `https://domaine/` refuse la connexion | Critique | Critique | Le domaine n'a pas son propre HTTPS |
| Idem, `https://domaine/` ne répond pas | Critique | Non évalué | Pas de réponse n'est pas un verdict : rien n'a été observé |

Les enregistrements MTA-STS et TLS-RPT sont désormais lus comme leurs RFC les écrivent (champs d'extension, espaces autour de `;`) : un enregistrement que la 0.3.1 jugeait invalide ou absent peut être reconnu valide, et inversement. Les deux restent « à améliorer » quand ils ne sont pas utilisables : la note ne bouge que lorsqu'un enregistrement devient valide.

Pour un domaine dont `http://` renvoie vers un autre site et dont le HTTPS ne répond jamais, aucun contrôle web ni TLS n'est évalué : la note peut désormais être absente (couverture inférieure à 50 %) là où la 0.3.0 et la 0.3.1 en donnaient une, en comptant la redirection en échec sans aucune réponse.

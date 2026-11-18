# Banc TLS (v0.8.0, PR-A)

Banc local, déterministe et reproductible, qui servira à éprouver tout outil de mesure TLS : le prototype de la PR-A2, puis la sonde du produit (PR-C), après la porte G1. Le banc ne contient **aucun code de produit**. Il n'ajoute aucune dépendance et n'entre pas dans l'image publiée (`tests/` est exclu par `.dockerignore`).

```bash
python -m pytest tests/tls_lab                      # le banc seul (≈ 10 s)
PYTHONPATH=tests python -m tls_lab.capabilities     # ce que le TLS de cet interpréteur sait faire
```

## Contenu

| Fichier | Rôle |
|---|---|
| `guard.py` | Garde de bouclage : un crochet d'audit refuse, avant tout paquet, toute connexion, liaison, résolution de nom ou commande qui ne vise pas cette machine. Seul `openssl` peut être lancé, vers une adresse de bouclage |
| `wire.py` | Octets TLS : constructeurs du premier envol d'un serveur, et lecteur strict qui en tire des faits (version, suite, groupe, échange de clés, alerte) ou refuse (`Malformed`). C'est l'oracle du banc, pas la sonde du produit |
| `servers.py` | Pairs TLS réels (module `ssl`), relais enregistreur, ClientHello réel écrit en mémoire, certificats de test |
| `responders.py` | Répondeurs synthétiques : lisent un ClientHello, puis répondent, répondent lentement, ferment, réinitialisent ou se taisent |
| `scenarios.json`, `scenarios.py` | Catalogue de 50 scénarios : offre, classe d'offre, réponse, faits attendus, niveau de preuve, empreinte SHA-256 ; une flotte de deux adresses |
| `mutations.py` | Corpus reproductible d'envols abîmés, pour les essais de robustesse |
| `capabilities.py` | Rapport JSON des capacités TLS, produit dans l'image en AMD64 et en ARM64 par la tâche de CI `tls-lab` |

## Précisions de la contre-revue du cadrage R1

1. **Pas d'attribution entre adresses.** Les faits attendus sont ceux d'une réponse, donc d'une adresse. La flotte `fleet.same_front_different_back` montre deux adresses de cette machine (127.0.0.1 et 127.0.0.2) identiques sur les offres essentielles et différentes sur une offre plus profonde (TLS 1.3 avec CCM_8). Une sonde qui recopierait un résultat d'une adresse à l'autre se trompera sur ce scénario.
2. **Offres modernes et protocoles anciens.** Chaque scénario porte une `offer_class` déduite de son offre (`scenarios.classify`). Une offre est `legacy` dès qu'un élément relève des anciens protocoles ou des suites faibles : SSLv3, TLS 1.0, TLS 1.1, DHE en TLS 1.2 (que les navigateurs récents ne proposent plus, et que le RFC 10015 interdit), échange RSA, 3DES, RC4, NULL, EXPORT, anonyme, ou courbe de moins de 256 bits. Le niveau standard de l'audit ne fera que des offres `modern` ; le niveau étendu, réservé aux domaines listés, fera les autres. Les serveurs réels portent la même classe.
3. **Comportement réel de TLS 1.2 et 1.3.** `test_real_tls.py` fait parler de vrais pairs OpenSSL à travers un relais enregistreur, et compare ce que rapporte OpenSSL avec ce que lit le lecteur dans l'envol enregistré. Sont couverts :
   - en TLS 1.2 : ECDHE P-256, X25519 et P-384, ChaCha20, ECDSA, et DHE 2048 et 1024 (configurations `legacy`) ;
   - en TLS 1.3 : le ServerHello et un vrai HelloRetryRequest ;
   - les alertes d'un vrai refus ;
   - TLS 1.0 et 1.1 quand l'OpenSSL local l'accepte ;
   - avec l'outil `openssl` : CCM_8 et un HelloRetryRequest pour P-384.

   Cette comparaison a déjà corrigé un défaut des fixtures synthétiques : avant TLS 1.2, la signature du ServerKeyExchange ne nomme pas son algorithme.
4. **Robustesse reproductible.** Le corpus de `mutations.py` est piloté par SHA-256 d'une graine et d'un compteur, sans le module `random`. Son empreinte est épinglée dans `test_robustness.py`. Limites :
   - les mutations sont aveugles à la sémantique de TLS au-delà des longueurs et des frontières d'enregistrement ;
   - il n'y a ni état, ni second envol, ni chronologie (les anomalies réseau sont des scénarios) ;
   - le corpus repose sur les 50 réponses du catalogue ;
   - aucune couverture n'est mesurée.

   La taille du corpus se règle par `TLS_LAB_FUZZ_COUNT` : 20 000 en CI, 100 000 exigés par la porte G1 sur le prototype de la PR-A2.
5. **Bouclage seulement.** La garde est active pendant chaque test du banc (`conftest.py`) ; un test prouve qu'elle refuse une adresse de documentation, un nom DNS et une commande autre qu'`openssl`. La politique de sortie du produit n'est ni utilisée ni modifiée : un test vérifie qu'elle refuse toujours le bouclage.

## Niveaux de preuve dans le catalogue

- `announced` : un ServerHello ou un HelloRetryRequest a choisi cette version, cette suite ou ce groupe pour cette offre.
- `alert_refusal` : alerte `handshake_failure`, `protocol_version` ou `insufficient_security`. Elle ne vaut refus **de cette offre** que si une offre de contrôle a obtenu un choix annoncé sur la même adresse, dans la même analyse (cadrage R1, § 3). Ce n'est jamais un refus définitif.
- `inconclusive` : toute autre alerte, fermeture, réinitialisation, silence ou réponse illisible.

## Limites connues du banc

- Le module `ssl` ne choisit pas les suites TLS 1.3 ni les groupes côté serveur, et ne propose pas SSLv3. L'outil `openssl` couvre une partie de ces cas quand il est installé ; sinon, les tests concernés sont sautés et comptés comme tels.
- RC4, 3DES et EXPORT ne sont plus disponibles dans les OpenSSL récents. Seules les réponses synthétiques les couvrent ; le rapport de capacités le dit pour chaque image.
- La flotte exige une seconde adresse de bouclage, ce qui est le cas sous Linux. Sinon, le test est sauté.
- Les tests IPv6 sont sautés sur une machine sans IPv6.

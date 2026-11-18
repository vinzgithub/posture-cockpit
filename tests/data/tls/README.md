# Paramètres DHE du banc TLS

Fichiers lus par `tests/tls_lab/servers.py` (`ServerConfig.dh`) pour les serveurs DHE du banc. Ce sont des paramètres de test : ils ne protègent rien et ne servent qu'à faire choisir à un vrai serveur OpenSSL un échange DHE de taille connue.

| Fichier | Taille | SHA-256 | Génération |
|---|---|---|---|
| `dh1024.pem` | 1024 bits (configuration ancienne, niveau étendu) | `de09ad344b4fe84bec76bdcdea3931b39dae413611e6bce9c3f0fd4d578dfea9` | `openssl dhparam -out dh1024.pem 1024` |
| `dh2048.pem` | 2048 bits | `4e7aed5d0ff85d3eba1f3e6d3a0348af1228172358f23a670aa0543c48d9155c` | `openssl dhparam -out dh2048.pem 2048` |

Générés le 18 novembre 2026 avec OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024). Une régénération change les octets mais pas les tests, qui ne lisent que la taille du nombre premier.

Le module `ssl` ne charge `dh1024.pem` qu'à un niveau de sécurité abaissé : au niveau par défaut de ces OpenSSL (2), une clé DH de moins de 2048 bits est refusée (`DH_KEY_TOO_SMALL`). Le banc utilise alors le niveau 0 (`@SECLEVEL=0`), des deux côtés.

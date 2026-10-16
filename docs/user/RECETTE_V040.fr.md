# Recette Docker de Posture Cockpit 0.4.0

Cette procédure utilise une copie du dépôt, une image locale, le port 8088, un volume
nommé `posture-cockpit-v040-recette-data` et un cookie propre à cette recette.
Le fichier `compose.yaml` de production n’est pas utilisé. Aucune image n’est publiée.

Les commandes sont à exécuter sur le serveur Docker. Garder les résultats pour
les examiner ensemble, notamment les versions, erreurs et éventuels tests ignorés.

## 1. Inventaire

🔎 Liste les conteneurs, images et ports déjà utilisés. Aucun changement.

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'
```

🔎 Vérifie si le port de recette est occupé. Une ligne d’écoute sur 8088 signifie
qu’il faut choisir ensemble un autre port avant de démarrer.

```bash
ss -ltn '( sport = :8088 )'
```

## 2. Copie isolée du code

⚠ Crée un nouveau répertoire de travail ; ne remplace aucun dépôt existant.
Si le répertoire existe déjà, arrêter cette étape et examiner son contenu.

```bash
git clone --single-branch --branch feat/v0.4-https-probe https://github.com/vinzgithub/posture-cockpit.git /opt/posture-cockpit-v040-recette-src
```

⚠ Place le terminal dans cette copie. Les commandes suivantes utilisent ce répertoire.

```bash
cd /opt/posture-cockpit-v040-recette-src
```

🔎 Affiche le commit testé. Il doit correspondre à celui annoncé dans la conversation.

```bash
git log -1 --oneline
```

🔎 Vérifie la configuration résolue : conteneur de recette, port 8088, volume et cookie distincts.

```bash
docker compose -f compose.recette-v040.yaml config
```

## 3. Construction

⚠ Construit l’image locale de recette, sans démarrer de conteneur ni publier d’image.
Le téléchargement de l’image Python et des dépendances nécessite Internet.

```bash
docker compose -f compose.recette-v040.yaml build --pull
```

🔎 Affiche Python et OpenSSL de l’image réellement construite, sans accès réseau ni volume applicatif existant.

```bash
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --entrypoint python posture-cockpit:v040-recette -c 'import sys,ssl; print(sys.version); print(ssl.OPENSSL_VERSION)'
```

## 4. TLS 1.0 et 1.1 dans l’environnement de l’image

⚠ Construit une image de tests séparée à partir de l’image de recette. Elle ajoute
pytest et les tests, sans remplacer le paquet installé dans l’image applicative.
Son fichier dockerignore spécifique inclut les tests, exclus du contexte applicatif normal.

```bash
docker build -f Dockerfile.recette-tests -t posture-cockpit:v040-recette-tests .
```

⚠ Exécute les tests dans un conteneur jetable, sans réseau externe. Les serveurs de
laboratoire écoutent uniquement en boucle locale dans ce conteneur ; aucune cible réelle.
Attendu : **5 passed, aucun skipped**. TLS 1.0 et TLS 1.1 sont chacun réellement négociés ;
les autres tests vérifient les requêtes minimales, la politique et la fermeture à l’échéance.
Un test ignoré n’est pas une validation du protocole concerné.

```bash
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true posture-cockpit:v040-recette-tests
```

## 5. Première recette avec une base neuve

⚠ Démarre uniquement le service de recette, avec son volume distinct.

```bash
docker compose -f compose.recette-v040.yaml up -d
```

🔎 Affiche son état ; attendre `healthy` après son démarrage.

```bash
docker compose -f compose.recette-v040.yaml ps
```

🔎 Vérifie la santé et la version : attendu HTTP 200, version 0.4.0.

```bash
curl --fail --show-error http://127.0.0.1:8088/healthz
```

🔎 Consulte uniquement les journaux de recette.

```bash
docker compose -f compose.recette-v040.yaml logs --tail=100
```

Ouvrir `http://<adresse-du-serveur>:8088`, créer le compte et cocher le domaine de
démonstration. Sur une base neuve, la démonstration doit rester à **57 C**.
Vérifier le plan, les détails, l’historique, le changement FR/EN, les boutons Copier,
les quatre indicateurs et les PDF courant/historique.

## 6. Migration d’une copie de base 0.3.2

Cette seconde phase se prépare après la réussite de la recette à vide : identifier
ensemble le chemin de la base et effectuer une sauvegarde SQLite cohérente, WAL compris.
La source et les destinations seront confirmées à partir de l’inventaire réel.
Seule la copie sera placée dans le volume de recette, conteneur de recette arrêté.
Aucun volume de production ne doit être monté dans cette instance de recette.

Sur la copie : vérifier la sauvegarde automatique avant migration, le schéma 4,
l’intégrité, les anciennes analyses et leurs adresses « — », les nouvelles valeurs API,
puis une revérification HTTPS et ses onze contrôles. Conserver la copie avant migration
pour comparer les lignes et refaire la procédure si nécessaire.

## 7. Arrêt de la recette

⚠ Arrête uniquement le projet de recette ; son volume et ses données sont conservés.

```bash
docker compose -f compose.recette-v040.yaml stop
```

Cette procédure ne fusionne aucune branche, ne crée aucune release et ne modifie pas
le conteneur de production. La bascule éventuelle fera l’objet d’une décision séparée.

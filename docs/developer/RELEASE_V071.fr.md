# Posture Cockpit v0.7.1 — dossier de livraison

**État : candidate en revue (PR-0), non publiée.** Spécification corrective approuvée sur son principe. Aucune fusion vers `main`, aucun tag, aucune publication GHCR et aucune intervention sur la production sans accord explicite du mainteneur.

## Périmètre

Version corrective de la 0.7.0, sans fonction nouvelle :

| # | Objet | Où |
|---|---|---|
| 1 | La phrase « le port 25 joint depuis cette instance ne garantit pas la livraison depuis Internet » n'apparaît que si la preuve enregistrée compte au moins un dialogue SMTP (`exhaustivity.dialogues > 0`) | `report/smtp.py`, `_smtp.html`, `report.html` |
| 2 | « Limites de la mesure » accorde chaque compteur au singulier ou au pluriel, en français et en anglais | `locales/fr.json`, `locales/en.json` (`smtp.limits`) |
| 3 | Les deux attributs `style` de la page d'historique, refusés par la politique de sécurité (CSP), sont retirés ; rendu inchangé (décision V1) | `history.html` |
| D7 | Les résultats d'une version plus récente que la 0.7.1 ne connaît pas sont présentés à part, bornés et échappés, sans effet sur aucun calcul | `unknown.py`, `_unknown.html`, plan, simulations, Mission Control, tableau de bord, PDF |

Les autres textes SMTP qui contiennent un compteur utilisaient déjà la syntaxe du catalogue (`{n:singulier|pluriel}`) ; `smtp.limits` était le seul texte en défaut.

## Invariants

- 21 contrôles, mêmes identifiants, poids, verdicts et preuves ; `GENERATION = 5` ; schéma SQLite 5, sans migration.
- La politique de sécurité envoyée est identique à celle de la 0.7.0 : ni `unsafe-inline`, ni empreinte, ni nonce. Un test compare l'en-tête envoyé.
- La page d'historique garde le rendu affiché depuis la 0.6 : la règle `.history-trend` de `app.css` (34rem au plus, 10rem de haut) est inchangée. Le navigateur appliquait déjà cette règle, puisque les styles en ligne étaient refusés.
- API : aucun champ ajouté, retiré ou modifié.
- Aucune donnée enregistrée n'est réécrite ni recalculée ; une revérification par la 0.7.1 recopie tels quels les résultats inconnus.

## Résultats d'une version plus récente (D7)

Un résultat est **inconnu** quand la version qui l'affiche n'a pas de titre pour lui (`<contrôle>.title` absent du catalogue). Ce critère est celui des pages et du PDF : il garantit qu'aucune clé brute n'est affichée.

| Endroit | Comportement |
|---|---|
| Détail et analyse de l'historique | Section à part « Résultats d'une version plus récente » : identifiant (en code), statut enregistré, effet sur la note (poids enregistré ou « sans effet »), catégorie, version qui a enregistré l'analyse, valeurs relevées en JSON |
| Bornes | 30 résultats listés au plus (puis « N autres… ») ; identifiant de 80 caractères ; version et catégorie de 40 caractères ; 4 Kio de valeurs par résultat à l'écran, la base gardant tout |
| Échappement | Échappement automatique de Jinja dans les deux environnements ; rien n'est marqué sûr ; aucun texte construit depuis une clé absente du catalogue |
| Plan de corrections, simulations | Jamais candidat ni hypothèse (`frozen` dans `core/scoring.py`) ; une simulation qui le demande est refusée (400) |
| Contrôles non évalués, dépendances HTTPS | Exclu |
| Mission Control, tableau de bord | Aucune transition ; les comparaisons lisent les statuts enregistrés comme en 0.7.0 |
| Événements | Aucun : une revérification recopie le statut enregistré, rien ne change |
| PDF | Une ligne en annexe, « N résultat(s) enregistré(s) par une version plus récente… : identifiants » (8 identifiants au plus) ; annexe et compte « les 21 contrôles » inchangés |
| Note, couverture, API | Calculées comme en 0.7.0, à partir de tous les constats enregistrés, avec leur poids enregistré |

### Écarts à la spécification, à valider

1. **Note affichée.** La spécification prévoyait d'afficher la note **enregistrée** pour une analyse d'un moteur plus récent. La candidate garde le calcul de la 0.7.0 : la note est recalculée à partir des constats enregistrés, chacun avec son poids enregistré. Un résultat informatif, comme les observations prévues en 0.8.0, n'y entre pas. Raisons :
   - pages, PDF, plan, simulations et API restent cohérents entre eux et identiques à la 0.7.0 ;
   - la note recalculée est égale à la note enregistrée tant que les règles sont celles de la génération 5.

   Une génération ultérieure pourrait les faire différer. Mais les comparaisons entre générations sont déjà refusées, et la 0.7.0 recalcule de la même façon.
2. **Critère « inconnu ».** Il repose sur le catalogue des textes, et non sur le registre des contrôles : c'est ce qui garantit l'absence de clé brute à l'écran comme dans le PDF.

### Limite connue

- **Nouveau statut.** Une version future qui enregistrerait un **statut** inconnu de la 0.7.1 (autre que ok, warn, fail, info, na, error, blocked) rendrait l'analyse illisible. La 0.7.1 la traite alors comme toute analyse corrompue, ce qu'elle faisait déjà en 0.7.0 : message dédié, sans erreur 500. Le cadrage de la 0.8.0 prévoit le statut `info` existant pour ses observations.
- **Liste des contrôles.** Une comparaison est refusée quand la liste des contrôles diffère entre deux états (`core/compare.py`, raison `checks`). La 0.8.0 devra donc tenir ses observations hors de la liste des contrôles des états, sans quoi activer l'audit bloquerait la comparaison des notes, contrairement à D4. C'est un point d'attention pour la PR-B de la 0.8.0, sans effet sur la 0.7.1.

## Compatibilité

| Sens | Effet |
|---|---|
| 0.7.0 → 0.7.1 | Changement d'image ; schéma 5, génération 5 ; aucune migration, aucun recalcul |
| 0.7.1 → 0.7.0 | Changement d'image, sans restauration. La 0.7.0 retrouve ses trois défauts d'affichage, sans effet sur les données |
| Version plus récente → 0.7.1 | Recommandé : les résultats inconnus sont présentés à part |
| Version plus récente → 0.7.0 | Déconseillé : la 0.7.0 afficherait les résultats inconnus par leurs clés brutes (comme le risque n° 9 de la 0.7.0) |
| 0.7.x → 0.6.1 | Inchangé (risque n° 9 de la 0.7.0, documenté) |

## Preuves

### Locales

- Suite complète : à reporter après la dernière exécution.
- `tests/test_v071_corrections.py` : les trois corrections, en FR et en EN, en page et en PDF. Pour D7 :
  - observation informative ;
  - contrôle noté inconnu, avec remède ;
  - dépendant HTTPS inconnu ;
  - identifiant, catégorie, version et preuve hostiles ou très longs ;
  - 41 résultats ;
  - revérification sans événement ;
  - simulation refusée ;
  - annexe du PDF bornée à la largeur de la page.
- `tests/browser/test_v071_history.py` (Chromium) : aucune violation de la politique de sécurité sur douze pages, et graphique de l'historique à la taille de la feuille de style. Contre-épreuve : avec le gabarit de la 0.7.0, le test échoue (`style-src-attr`).
- Ruff et mypy : réussis.

### CI

À reporter : run complet, tâche `upgrade (v0.7.0)`, qui fait l'aller-retour 0.7.0 → 0.7.1 → 0.7.0 → 0.7.1 depuis l'image officielle épinglée par son digest `sha256:edc18c687847d2a9d1475d0f88fbfca117295eda0be7a998b0194e380982fd53`, et essai à blanc de `release`.

## Recette (à faire, sur un LXC distinct de la production)

1. Image locale construite depuis le commit à recetter ; scripts `install`, `upgrade` depuis la 0.7.0 par digest, `rollback`.
2. Copie restaurée de la production :
   - montée en 0.7.1 ;
   - corrections 1 à 3, en page et en PDF, console du navigateur sans violation ;
   - parcours de toutes les pages et de tous les PDF ;
   - retour en 0.7.0, puis nouvelle montée.
3. Analyse « version plus récente » injectée dans une instance de test seulement : affichage à part, plan et simulations inchangés.

## Publication

À renseigner après les opérations, sur accord explicite : PR vers `main`, tag, GitHub Release, workflow GHCR, digests.

# Écrire une extension

🇬🇧 [English version](EXTENSIONS.md)

Une extension ajoute des contrôles à Posture Cockpit. Les contrôles intégrés (`mail`, `tls`, `web`, `dns`) sont eux-mêmes des extensions : leur code, dans `src/posture_cockpit/checks/`, est le meilleur modèle.

Un exemple complet et testé se trouve dans [`examples/posture-cockpit-example`](../../examples/posture-cockpit-example) : copiez ce dossier pour commencer.

## 1. Ce qu'il faut

```
mon-extension/
├── pyproject.toml                    # déclare le point d'entrée
└── posture_cockpit_monext/
    ├── __init__.py                   # l'objet Extension et les contrôles
    └── locales/
        ├── monext.fr.json            # les textes en français
        └── monext.en.json            # … et en anglais
```

Dans `pyproject.toml`, la ligne qui fait trouver l'extension :

```toml
[project.entry-points."posture_cockpit.extensions"]
monext = "posture_cockpit_monext:extension"
```

## 2. Un contrôle

```python
from pathlib import Path

from posture_cockpit.core import CheckContext, Effort, Extension, Outcome, Remedy, load_messages, na, ok, warn

extension = Extension(
    "monext",                                   # identifiant : minuscules, chiffres, _
    name="Mon extension",
    version="1.0.0",
    description="Ce que vérifient ces contrôles.",
    messages=load_messages(Path(__file__).parent / "locales", "monext"),
)


@extension.check("permissions_policy", category="web", weight=1)
async def permissions_policy(ctx: CheckContext) -> Outcome:
    hosts = await ctx.web_hosts()
    if not hosts:
        return na("monext.permissions_policy.no_website")
    page = await ctx.net.http_get(f"https://{hosts[0]}/")
    if page.header("permissions-policy"):
        return ok("monext.permissions_policy.ok")
    return warn("monext.permissions_policy.missing",
                Remedy(10, Effort.DELEGATE, message="monext.permissions_policy.message"),
                {"url": page.url}, host=hosts[0])
```

- L'identifiant du contrôle devient `monext.permissions_policy` ; il est enregistré avec chaque résultat, **ne le changez plus** une fois publié.
- `category` : `mail`, `web`, `tls`, `dns`, ou une catégorie à vous (ajoutez alors les textes `category.<nom>`).
- `weight` : de 1 (détail) à 10 (essentiel).
- `internal=False` (facultatif) : le contrôle n'a de sens que sur Internet (un enregistrement DNS ou de messagerie vu de l'extérieur) ; dans l'analyse d'un périmètre interne, il est déclaré « non applicable » sans être lancé.

## 3. Ce que reçoit un contrôle : `CheckContext`

| Attribut ou méthode | Rôle |
|---|---|
| `ctx.domain` | Le domaine, en minuscules, en ASCII |
| `ctx.now` | L'heure de l'analyse (UTC) |
| `ctx.internal` | Vrai quand l'analyse a lieu dans un périmètre interne |
| `await ctx.net.dns(nom, "TXT")` | Une requête DNS : `.records` (textes) et `.exists` (faux si le nom n'existe pas) |
| `await ctx.net.certificate(hôte)` | Le certificat présenté sur le port 443, et s'il est reconnu |
| `await ctx.net.accepts_tls(hôte, "TLSv1.1")` | Vrai, faux, ou `None` si cette machine ne peut pas essayer |
| `await ctx.net.http_get(url)` | Un GET, sans suivre les redirections : `.status`, `.header(nom)`, `.body` (64 Ko au plus). Le certificat n'est pas vérifié (les contrôles TLS le jugent), sauf avec `verify=True` |
| `await ctx.txt(nom)` | Raccourci : les enregistrements TXT d'un nom |
| `await ctx.web_hosts()` | Le domaine et `www`, ceux qui ont une adresse |
| `await ctx.shared(clé, fonction)` | Calcule une chose une seule fois par analyse, pour tous les contrôles qui en ont besoin |

**Restez passif** : tout passe par `ctx.net`. Pas de socket ouverte à la main, pas de scan de ports, pas de formulaire envoyé. `ctx.net` applique à chaque connexion la **règle de sortie** de l'analyse (adresses publiques sur les ports 80 et 443 sur Internet, les réseaux du périmètre en interne) : une redirection que vous suivez est un nouveau `http_get`, vérifié comme le premier. Ouvrir une socket vous-même contournerait cette règle : une extension est du code qui tourne avec les droits de l'application, c'est pourquoi on n'installe que des extensions de confiance.

**Les erreurs** : `ctx.net` lève `NetworkError` quand il n'obtient pas de réponse exploitable, ou l'une de ses sous-classes :

| Exception | Sens |
|---|---|
| `NetworkError` | Pas de réponse (délai dépassé, échec DNS…) |
| `Refused` | L'adresse répond mais rien n'écoute sur ce port : une réponse nette |
| `DestinationBlocked` | La règle de sortie a refusé la connexion (adresse privée sur Internet, port non autorisé…) |
| `UntrustedCertificate` | Seulement avec `http_get(url, verify=True)` : le certificat n'est pas valide (`.problem` dit pourquoi) |

Ne les attrapez pas sauf si la réponse a un sens pour votre contrôle (MTA-STS lit `Refused` comme « pas de serveur de politique ») : le moteur affichera le contrôle « non évalué », avec la raison, et il fera baisser la couverture de l'analyse. Un contrôle qui plante ou dépasse son délai est traité de la même façon, sans gêner les autres.

## 4. Ce que renvoie un contrôle

| Fonction | État | Dans la note |
|---|---|---|
| `ok(clé, evidence, **params)` | Conforme | Tout le poids |
| `warn(clé, remedy, evidence, **params)` | À améliorer | La moitié |
| `fail(clé, remedy, evidence, **params)` | Critique | Rien |
| `na(clé, evidence, **params)` | Non applicable (pas de site web, pas de messagerie…) | Écarté |
| `info(clé, evidence, **params)` | Information, rien à juger | Écarté |
| `not_evaluated(clé, evidence, **params)` | S'applique, mais aucun verdict n'a pu être rendu | Écarté, et fait baisser la couverture |

Dites « non applicable » seulement quand le contrôle ne concerne vraiment pas le domaine ; quand il le concerne mais n'a pas pu être fait, il est « non évalué ». La différence compte : sous 50 % de couverture, le domaine n'a pas de note (voir [SCORING.fr.md](../user/SCORING.fr.md)).

- `clé` : la clé du texte qui décrit le constat (jamais une phrase).
- `evidence` : un dictionnaire des valeurs brutes relevées, affiché sur la page technique.
- `params` : les valeurs utilisées dans les textes (`{host}`, `{days:jour|jours}`, `{expires_on}` pour une date ISO).
- `Remedy(minutes, effort, dns=…, message=…, how=…)` : comment corriger.
  - `dns=(DnsChange("add", "TXT", "_dmarc", "v=DMARC1; p=none"),)` : la page affiche les étapes chez l'hébergeur DNS et l'enregistrement à copier ;
  - `message="monext.x.message"` : un message prêt à envoyer au prestataire ;
  - `how="monext.x.how"` : une explication courte.

## 5. Les textes

`locales/monext.fr.json` :

```json
{
  "monext.permissions_policy.title": "Fonctions du navigateur restreintes",
  "monext.permissions_policy.action": "Restreindre les fonctions du navigateur",
  "monext.permissions_policy.why": "Cet en-tête dit au navigateur que le site n'utilise ni caméra, ni micro…",
  "monext.permissions_policy.ref": "W3C, Permissions Policy",
  "monext.permissions_policy.ok": "Le site restreint les fonctions du navigateur.",
  "monext.permissions_policy.missing": "{host} n'envoie pas d'en-tête Permissions-Policy.",
  "monext.permissions_policy.no_website": "Pas de site web : ce contrôle ne s'applique pas.",
  "monext.permissions_policy.message": "Bonjour,\n\nPourriez-vous ajouter sur {host} l'en-tête…\n\nMerci d'avance."
}
```

Le même fichier en anglais, avec les mêmes clés. `{domain}` est toujours disponible dans les textes. Deux clés facultatives traduisent le nom et la description de l'extension sur la page d'administration : `monext.extension.name` et `monext.extension.description`.

## 6. Tester

Les tests de Posture Cockpit montrent comment lancer un contrôle sur des réponses enregistrées, sans réseau :

```python
from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork

data = {"dns": {"exemple.fr A": ["192.0.2.10"]},
        "http": {"https://exemple.fr/": {"status": 200, "headers": {"Permissions-Policy": "camera=()"}}}}
result = asyncio.run(engine.scan("exemple.fr", extension.checks, FixtureNetwork(data)))
assert result.findings[0].status.value == "ok"
```

Puis, sur un vrai domaine : `pip install -e .` dans le dossier de l'extension, et `posture-cockpit scan exemple.fr`.

## 7. Installer

- **Avec pip** : `pip install posture-cockpit-monext` (ou le chemin du dossier), puis redémarrer.
- **Avec Docker** : une image qui part de la nôtre :

  ```dockerfile
  FROM ghcr.io/vinzgithub/posture-cockpit:0.4.1
  USER root
  COPY mon-extension /tmp/mon-extension
  RUN pip install --no-cache-dir /tmp/mon-extension && rm -rf /tmp/mon-extension
  USER 10001:10001
  ```

  Puis, dans le `.env` de l'installation : `POSTURE_COCKPIT_IMAGE=<votre image>`, et `docker compose up -d`.

`posture-cockpit extensions` liste ce qui est chargé ; la page **Administration** aussi, avec un interrupteur par extension et l'erreur exacte d'une extension qui n'a pas pu être chargée.

## Contrat de remédiation v0.6.1

`Remedy.expect` indique le statut attendu après l’étape proposée, pas un résultat observé. Toute nouvelle écriture sérialise cette clé, y compris `"ok"` (défaut), `"warn"`, `"info"` ou `null` (effet inconnu). Pour les types intégrés reconnus par l’adaptateur, la table courante prévaut sur la valeur stockée ; la valeur stockée ne fait foi que pour les types inconnus, notamment les extensions. Une extension historique sans clé reste inconnue ; son ancienne intention OK ne peut pas être reconstruite. Aucun ancien JSON n’est réécrit. La v0.5.0 ignore cette clé et peut l’omettre lors de ses propres nouvelles écritures ; la remontée conserve alors l’interprétation historique prudente.

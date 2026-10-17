# Writing an extension

🇫🇷 [Version française](EXTENSIONS.fr.md)

An extension adds checks to Posture Cockpit. The built-in checks (`mail`, `tls`, `web`, `dns`) are themselves extensions: their code, in `src/posture_cockpit/checks/`, is the best model.

A complete, tested example is in [`examples/posture-cockpit-example`](../../examples/posture-cockpit-example): copy that folder to start.

## 1. What you need

```
my-extension/
├── pyproject.toml                    # declares the entry point
└── posture_cockpit_myext/
    ├── __init__.py                   # the Extension object and the checks
    └── locales/
        ├── myext.fr.json             # texts in French
        └── myext.en.json             # … and in English
```

In `pyproject.toml`, the line that makes the extension found:

```toml
[project.entry-points."posture_cockpit.extensions"]
myext = "posture_cockpit_myext:extension"
```

## 2. A check

```python
from pathlib import Path

from posture_cockpit.core import CheckContext, Effort, Extension, Outcome, Remedy, load_messages, na, ok, warn

extension = Extension(
    "myext",                                    # id: lower-case letters, digits, _
    name="My extension",
    version="1.0.0",
    description="What these checks look at.",
    messages=load_messages(Path(__file__).parent / "locales", "myext"),
)


@extension.check("permissions_policy", category="web", weight=1)
async def permissions_policy(ctx: CheckContext) -> Outcome:
    hosts = await ctx.web_hosts()
    if not hosts:
        return na("myext.permissions_policy.no_website")
    page = await ctx.net.http_get(f"https://{hosts[0]}/")
    if page.header("permissions-policy"):
        return ok("myext.permissions_policy.ok")
    return warn("myext.permissions_policy.missing",
                Remedy(10, Effort.DELEGATE, message="myext.permissions_policy.message"),
                {"url": page.url}, host=hosts[0])
```

- The check id becomes `myext.permissions_policy`; it is stored with every result, **do not change it** once released.
- `category`: `mail`, `web`, `tls`, `dns`, or one of your own (then add the `category.<name>` texts).
- `weight`: from 1 (detail) to 10 (essential).
- `internal=False` (optional): the check only makes sense on the Internet (a DNS or mail record seen from outside); in a scan of an internal perimeter it is reported "not applicable" without running.

## 3. What a check receives: `CheckContext`

| Attribute or method | Role |
|---|---|
| `ctx.domain` | The domain, lower case, ASCII |
| `ctx.now` | Time of the scan (UTC) |
| `ctx.internal` | True when the scan runs in an internal perimeter |
| `await ctx.net.dns(name, "TXT")` | A DNS query: `.records` (texts) and `.exists` (false when the name does not exist) |
| `await ctx.net.certificate(host)` | The certificate presented on port 443, and whether it is trusted |
| `await ctx.net.accepts_tls(host, "TLSv1.1")` | True, false, or `None` when this machine cannot try |
| `await ctx.net.http_get(url)` | One GET, redirects not followed: `.status`, `.header(name)`, `.body` (64 KiB at most). The certificate is not checked (the TLS checks judge it) unless you pass `verify=True` |
| `await ctx.txt(name)` | Shortcut: the TXT records of a name |
| `await ctx.web_hosts()` | The domain and `www`, those that have an address |
| `await ctx.shared(key, function)` | Computes something once per scan, for every check that needs it |

**Stay passive**: everything goes through `ctx.net`. No socket opened by hand, no port scan, no form submitted. `ctx.net` applies the scan's **egress rule** to every connection (public addresses on ports 80 and 443 on the Internet, the perimeter's networks inside): a redirection you follow is a new `http_get`, checked like the first one. Opening a socket yourself would bypass that rule: an extension is code that runs with the application's rights, which is why only trusted extensions should be installed.

**Errors**: `ctx.net` raises `NetworkError` when it gets no usable answer, or one of its subclasses:

| Exception | Meaning |
|---|---|
| `NetworkError` | No answer (timeout, DNS failure…) |
| `Refused` | The address answered but nothing listens on that port: a definite answer |
| `DestinationBlocked` | The egress rule refused the connection (private address on the Internet, port not allowed…) |
| `UntrustedCertificate` | Only with `http_get(url, verify=True)`: the certificate is not valid (`.problem` says why) |

Do not catch them unless the answer means something for your check (MTA-STS treats `Refused` as "no policy server"): the engine shows the check as "not evaluated", with the reason, and it lowers the coverage of the scan. A check that crashes or times out is handled the same way, without disturbing the others.

## 4. What a check returns

| Function | Status | In the score |
|---|---|---|
| `ok(key, evidence, **params)` | Compliant | The full weight |
| `warn(key, remedy, evidence, **params)` | To improve | Half |
| `fail(key, remedy, evidence, **params)` | Critical | Nothing |
| `na(key, evidence, **params)` | Not applicable (no website, no mail…) | Left out |
| `info(key, evidence, **params)` | Information, nothing to judge | Left out |
| `not_evaluated(key, evidence, **params)` | Applies, but no verdict could be reached | Left out, and lowers the coverage |

Say "not applicable" only when the check really does not concern the domain; when it does but could not be done, it is "not evaluated". The difference matters: below 50 % coverage the domain gets no score (see [SCORING.md](../user/SCORING.md)).

- `key`: the key of the text that describes the finding (never a sentence).
- `evidence`: a dictionary of the raw values found, shown on the technical page.
- `params`: the values used in the texts (`{host}`, `{days:day|days}`, `{expires_on}` for an ISO date).
- `Remedy(minutes, effort, dns=…, message=…, how=…)`: how to fix it.
  - `dns=(DnsChange("add", "TXT", "_dmarc", "v=DMARC1; p=none"),)`: the page shows the steps at the DNS host and the record to copy;
  - `message="myext.x.message"`: a ready-to-send message for the provider;
  - `how="myext.x.how"`: a short explanation.

## 5. Texts

`locales/myext.en.json`:

```json
{
  "myext.permissions_policy.title": "Browser features restricted",
  "myext.permissions_policy.action": "Restrict browser features",
  "myext.permissions_policy.why": "This header tells the browser that the website uses no camera, microphone…",
  "myext.permissions_policy.ref": "W3C, Permissions Policy",
  "myext.permissions_policy.ok": "The website restricts browser features.",
  "myext.permissions_policy.missing": "{host} sends no Permissions-Policy header.",
  "myext.permissions_policy.no_website": "No website: this check does not apply.",
  "myext.permissions_policy.message": "Hello,\n\nCould you add on {host} the header…\n\nThank you."
}
```

The same file in French, with the same keys. `{domain}` is always available in texts. Two optional keys translate the extension's name and description on the administration page: `myext.extension.name` and `myext.extension.description`.

## 6. Testing

Posture Cockpit's tests show how to run a check against recorded answers, without network:

```python
from posture_cockpit.core import engine
from posture_cockpit.core.fixture import FixtureNetwork

data = {"dns": {"example.com A": ["192.0.2.10"]},
        "http": {"https://example.com/": {"status": 200, "headers": {"Permissions-Policy": "camera=()"}}}}
result = asyncio.run(engine.scan("example.com", extension.checks, FixtureNetwork(data)))
assert result.findings[0].status.value == "ok"
```

Then, on a real domain: `pip install -e .` in the extension folder, and `posture-cockpit scan example.com`.

## 7. Installing

- **With pip**: `pip install posture-cockpit-myext` (or the folder's path), then restart.
- **With Docker**: an image based on ours:

  ```dockerfile
  FROM ghcr.io/vinzgithub/posture-cockpit:0.4.1
  USER root
  COPY my-extension /tmp/my-extension
  RUN pip install --no-cache-dir /tmp/my-extension && rm -rf /tmp/my-extension
  USER 10001:10001
  ```

  Then, in the `.env` of the installation: `POSTURE_COCKPIT_IMAGE=<your image>`, and `docker compose up -d`.

`posture-cockpit extensions` lists what is loaded; so does the **Administration** page, with a switch per extension and the exact error of an extension that could not be loaded.

# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Example extension: is the browser told which powerful features the website does not use?

The Permissions-Policy header lets a website say "no camera, no microphone, no
location here". A script injected into the page can then not ask for them.

Everything an extension needs is here: an Extension object, one check function
decorated with @extension.check, and its texts in locales/example.<lang>.json.
"""

from __future__ import annotations

from pathlib import Path

from posture_cockpit.core import CheckContext, Effort, Extension, Outcome, Remedy, info, load_messages, ok, warn

extension = Extension(
    "example",
    name="Exemple : Permissions-Policy",
    version="1.0.0",
    description="Example extension: the Permissions-Policy header.",
    messages=load_messages(Path(__file__).parent / "locales", "example"),
)


@extension.check("permissions_policy", category="web", weight=1)
async def permissions_policy(ctx: CheckContext) -> Outcome:
    """The home page should send a Permissions-Policy header."""
    hosts = await ctx.web_hosts()  # the domain and www, those that have an address
    if not hosts:
        return info("example.permissions_policy.no_website")
    # The first home page that is not a redirection. If the server does not
    # answer, ctx.net raises NetworkError and the engine shows the check as
    # "could not be checked": nothing to handle here.
    for host in hosts:
        page = await ctx.net.http_get(f"https://{host}/")
        if not 300 <= page.status < 400:
            break
    header = page.header("permissions-policy")
    if header:
        return ok("example.permissions_policy.ok", {"header": header})
    remedy = Remedy(10, Effort.DELEGATE, message="example.permissions_policy.message")
    return warn("example.permissions_policy.missing", remedy, {"url": page.url}, host=host)

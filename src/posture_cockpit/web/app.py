# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Builds the FastAPI application: services, security headers, session, routes.

Run with:  uvicorn --factory posture_cockpit.web.app:create_app
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__
from ..config import Config, secret_key
from ..core.network import Network
from ..core.registry import Registry
from ..i18n import Catalog
from ..scanner import Scanner
from ..security import LoginThrottle
from ..storage import Accounts, AuditLog, Database, InstanceSettings, Perimeters, Scans
from . import deps
from .limits import ScanLimiter
from .routes import account, admin, api, auth, domains, perimeters, report
from .services import STATIC_DIR, TEMPLATES_DIR, Services

# Strict policy: no inline script or style, nothing loaded from elsewhere.
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; "
       "form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors {frame_ancestors}")


def create_app(config: Config | None = None, registry: Registry | None = None,
               network_factory: Callable[[str], Network] | None = None) -> FastAPI:
    """``registry`` and ``network_factory`` let the tests use their own checks and recorded answers."""
    config = config or Config.from_env()
    registry = registry or Registry.discover()
    db = Database(config.db_path)
    settings = InstanceSettings(db)
    services = Services(
        config=config, db=db, accounts=Accounts(db), scans=Scans(db), perimeters=Perimeters(db), audit=AuditLog(db),
        settings=settings, registry=registry,
        catalog=Catalog(registry.messages),
        scanner=Scanner(registry, config, disabled=settings.disabled_extensions, network_factory=network_factory),
        throttle=LoginThrottle(), account_throttle=LoginThrottle(max_failures=10, lock_seconds=900),
        scan_limiter=ScanLimiter(config.max_concurrent_scans, config.scans_per_hour),
        templates=Jinja2Templates(directory=TEMPLATES_DIR),
    )

    app = FastAPI(title="Posture Cockpit", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services = services
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP.format(frame_ancestors=config.frame_ancestors)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if config.cookie_secure:  # served over HTTPS: browsers must not come back over HTTP
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.add_middleware(SessionMiddleware, secret_key=secret_key(config.data_dir), session_cookie="posture_cockpit",
                       max_age=config.session_max_age, same_site="lax", https_only=config.cookie_secure)

    _add_error_pages(app)
    for module in (auth, account, admin, perimeters, domains, report, api):
        app.include_router(module.router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "version": __version__}

    return app


def _wants_json(request: Request) -> bool:
    return (request.url.path.startswith("/api/") or request.headers.get("x-csrf-token") is not None
            or "application/json" in request.headers.get("accept", ""))


def _add_error_pages(app: FastAPI) -> None:
    """Turns the access exceptions of deps.py into redirects, or JSON for scripts."""
    redirects = {
        deps.NeedSetup: ("/setup", 401, "setup required"),
        deps.NeedLogin: ("/login", 401, "login required"),
        deps.NeedPasswordChange: ("/account/password", 403, "password change required"),
        deps.NeedAdminConfirm: ("/admin/confirm", 403, "admin confirmation required"),
    }

    def redirect_handler(url: str, status: int, message: str):
        async def handler(request: Request, exc: Exception):
            if _wants_json(request):
                return JSONResponse({"error": message}, status_code=status)
            return deps.redirect(url)
        return handler

    for exc_class, (url, status, message) in redirects.items():
        app.add_exception_handler(exc_class, redirect_handler(url, status, message))

    @app.exception_handler(deps.CsrfError)
    async def csrf_error(request: Request, exc: deps.CsrfError):
        if _wants_json(request):
            return JSONResponse({"error": "invalid CSRF token"}, status_code=403)
        return deps.render(request, "error.html", status=403, message=deps.t(request, "error.csrf"))

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if _wants_json(request):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        key = {404: "error.not_found", 403: "error.forbidden"}.get(exc.status_code, "error.generic")
        return deps.render(request, "error.html", status=exc.status_code, message=deps.t(request, key))

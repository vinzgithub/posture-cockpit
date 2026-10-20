# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Builds the FastAPI application: services, security headers, session, routes.

Run with:  uvicorn --factory posture_cockpit.web.app:create_app
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__
from ..config import Config, StartupError, prepare_data_dir, secret_key
from ..core.network import Network
from ..core.registry import Registry
from ..i18n import Catalog
from ..scanner import Scanner
from ..security import LoginThrottle
from ..storage import Accounts, AuditLog, CorruptScan, InstanceSettings, Perimeters, Scans, instance_lock, open_database
from ..storage.schedules import Schedules
from . import deps, first_run
from .limits import ScanLimiter
from .routes import account, admin, api, auth, domains, events, perimeters, report
from .scheduler import Scheduler
from .services import STATIC_DIR, TEMPLATES_DIR, Services

# Strict policy: no inline script or style, nothing loaded from elsewhere.
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; "
       "form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors {frame_ancestors}")

log = logging.getLogger("uvicorn.error")


def create_app(config: Config | None = None, registry: Registry | None = None,
               network_factory: Callable[[str], Network] | None = None) -> FastAPI:
    """``registry`` and ``network_factory`` let the tests use their own checks and recorded answers."""
    config = config or Config.from_env()
    registry = registry or Registry.discover()
    try:
        # A folder the application cannot write, an unknown schema or a damaged key stop the start
        # here, with a message saying what to do, rather than with an error on the first request.
        prepare_data_dir(config.data_dir)
        # Shared with the commands, never with a restoration (storage/instance_lock.py): kept until
        # the application stops.
        try:
            folder_lock = instance_lock.shared(config.data_dir)
        except instance_lock.Busy:
            raise StartupError(f"A restoration is in progress on {config.data_dir}: start again once it is "
                               "finished.") from None
        try:
            # A verified backup archive is written before any migration (storage/upgrade.py).
            db = open_database(config, say=log.warning)
            session_key = secret_key(config.data_dir)
        except BaseException:
            folder_lock.release()
            raise
    except StartupError as error:
        log.error("Posture Cockpit cannot start: %s", error)
        raise
    settings = InstanceSettings(db)
    services = Services(
        config=config, db=db, accounts=Accounts(db), scans=Scans(db), perimeters=Perimeters(db), audit=AuditLog(db),
        settings=settings, registry=registry,
        catalog=Catalog(registry.messages),
        scanner=Scanner(registry, config, disabled=settings.disabled_extensions, network_factory=network_factory),
        throttle=LoginThrottle(), account_throttle=LoginThrottle(max_failures=10, lock_seconds=900),
        scan_limiter=ScanLimiter(config.max_concurrent_scans, config.scans_per_hour),
        templates=Jinja2Templates(directory=TEMPLATES_DIR),
        schedules=Schedules(db, config.timezone),
    )

    app = FastAPI(title="Posture Cockpit", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services = services
    app.state.folder_lock = folder_lock
    # Scheduled scans (web/scheduler.py): started with the application, stopped before the lock goes.
    app.state.scheduler = Scheduler(services, services.schedules) if config.scheduler else None
    if app.state.scheduler is not None:
        app.router.on_startup.append(app.state.scheduler.start)
        app.router.on_shutdown.append(app.state.scheduler.stop)
    app.router.on_shutdown.append(folder_lock.release)
    # While no account exists, /setup asks for a one-time code written to the log (first_run.py).
    app.state.setup_code = None
    if services.accounts.count() == 0:
        app.state.setup_code = first_run.prepare(db, config.setup_code)
        first_run.announce(app.state.setup_code, configured=bool(config.setup_code))
    else:
        first_run.clear(db)
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

    app.add_middleware(SessionMiddleware, secret_key=session_key, session_cookie=config.session_cookie,
                       max_age=config.session_max_age, same_site="lax", https_only=config.cookie_secure)

    _add_error_pages(app)
    for module in (auth, account, admin, perimeters, domains, events, report, api):
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
            if isinstance(exc, deps.NeedAdminConfirm):
                # A confirmation unlocks the original page, never replays a POST.
                # A schedule form returns to its GET details page, not /admin.
                path = request.url.path
                target = "/admin"
                if request.method == "GET":
                    target = path + (f"?{request.url.query}" if request.url.query else "")
                elif request.method == "POST" and path.startswith("/domains/") and path.endswith("/schedule"):
                    target = path[:-len("/schedule")] + "/details#schedule"
                request.session["admin_return"] = deps.local_path(target, "/admin")
            return deps.redirect(url)
        return handler

    for exc_class, (url, status, message) in redirects.items():
        app.add_exception_handler(exc_class, redirect_handler(url, status, message))

    @app.exception_handler(CorruptScan)
    async def corrupt_scan(request: Request, exc: CorruptScan):
        if _wants_json(request):
            return JSONResponse({"error": "scan_unreadable", "scan_id": exc.scan_id}, status_code=409)
        if request.url.path.endswith("/report.pdf"):
            from ..report import ReportUnavailable, build_unreadable_pdf

            try:
                pdf = build_unreadable_pdf(request.app.state.services.catalog, deps.lang_of(request))
                return Response(pdf, status_code=409, media_type="application/pdf")
            except ReportUnavailable:
                pass
        return deps.render(request, "error.html", status=409, message=deps.t(request, "error.scan_unreadable"))

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

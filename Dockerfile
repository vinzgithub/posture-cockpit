# syntax=docker/dockerfile:1
# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

# ---- build the wheel
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir build==1.2.2 && python -m build --wheel --outdir /dist

# ---- runtime image
FROM python:3.12-slim
LABEL org.opencontainers.image.title="Posture Cockpit" \
      org.opencontainers.image.description="Passive security check of a domain, with a guided plan of fixes" \
      org.opencontainers.image.source="https://github.com/vinzgithub/posture-cockpit" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POSTURE_COCKPIT_DATA_DIR=/data \
    XDG_CACHE_HOME=/tmp/cache
# Pango and HarfBuzz are what WeasyPrint needs to draw the PDF report.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 cockpit \
 && useradd --system --uid 10001 --gid cockpit --home-dir /data --shell /usr/sbin/nologin cockpit \
 && mkdir -p /data && chown cockpit:cockpit /data
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER cockpit
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
CMD ["uvicorn", "--factory", "posture_cockpit.web.app:create_app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]

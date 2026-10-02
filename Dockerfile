# LINCHPIN API + web UI. Read-only: parses exports, sends no packets.
#   docker build -t linchpin . && docker run --rm -p 127.0.0.1:8000:8000 linchpin
# Base image pinned by digest (Dependabot's docker ecosystem keeps it current); runtime
# dependencies installed from the hash-pinned requirements.lock, the wheel itself without deps.
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY src ./src
RUN pip install --no-cache-dir "build==1.6.1" && python -m build --wheel --outdir /dist

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.lock /tmp/requirements.lock
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
 && pip install --no-cache-dir --no-deps /tmp/*.whl && rm -f /tmp/*.whl /tmp/requirements.lock \
 && useradd --create-home --uid 10001 linchpin
USER linchpin
WORKDIR /home/linchpin
COPY --chown=linchpin scenarios ./scenarios
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/stats')"
# Inside the container the API listens on all interfaces so `-p 127.0.0.1:8000:8000` can reach it;
# the Host-header allow-list (LINCHPIN_ALLOWED_HOSTS) still only answers localhost names.
CMD ["uvicorn", "linchpin.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

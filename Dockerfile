# LINCHPIN API + web UI. Read-only: parses exports, sends no packets.
#   docker build -t linchpin . && docker run --rm -p 127.0.0.1:8000:8000 linchpin
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /dist/*.whl /tmp/
RUN WHL=$(ls /tmp/linchpin-*.whl) && pip install --no-cache-dir "${WHL}[api]" && rm -f /tmp/*.whl \
 && useradd --create-home --uid 10001 linchpin
USER linchpin
WORKDIR /home/linchpin
COPY --chown=linchpin scenarios ./scenarios
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/stats')"
CMD ["uvicorn", "linchpin.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

"""Browser smoke tests for the path explorer (live API and static Pages demo).

Skipped unless Playwright and a Chromium build are installed:
    pip install playwright && python -m playwright install chromium
The page loads Cytoscape.js from a CDN, so these tests need network access.
"""
import functools
import http.server
import socket
import threading
import time
from pathlib import Path

import pytest

pw = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.ui

DEMO = Path(__file__).resolve().parents[1] / "docs" / "demo"


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # browser binaries not installed
            pytest.skip(f"chromium unavailable: {e}")
        yield b
        b.close()


def _check_explorer(page, url: str) -> None:
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(url)
    page.wait_for_selector("tr.rem[data-i]", timeout=30000)
    assert "nodes" in page.inner_text("#stats")
    assert page.locator("tr.rem[data-i]").count() >= 1
    assert "minimum cut" in page.inner_text("#cut")
    n = page.evaluate("cy.nodes().length")
    assert n > 10
    # what-if: remove the first remediation's target via the same code path as a node click
    target = page.evaluate("""async () => { const r = await api('/remediations?budget=3');
        removed.add(r[0].target_node); await whatif(); return r[0].target_node; }""")
    assert target
    page.wait_for_selector("#whatif .delta", timeout=10000)
    assert "paths" in page.inner_text("#whatif")
    assert not errors, errors


def test_static_demo(browser):
    if not (DEMO / "index.html").exists():
        pytest.skip("static demo not built (scripts/build_static_demo.py)")
    port = _port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(DEMO))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        page = browser.new_page()
        _check_explorer(page, f"http://127.0.0.1:{port}/index.html")
        page.select_option("#family", "ad")
        page.click("#load")
        page.wait_for_function("document.querySelector('#stats').textContent.includes('nodes')")
    finally:
        srv.shutdown()


def test_live_api_ui(browser):
    uvicorn = pytest.importorskip("uvicorn")
    from linchpin.api.app import create_app
    from linchpin.config import Config
    from linchpin.graph.store import GraphStore
    from linchpin.synth.topologies import generate_family

    findings, _ = generate_family("single", 16, 0)
    s = GraphStore(Config())
    s.upsert_findings(findings)
    s.build_attack_graph()
    port = _port()
    server = uvicorn.Server(uvicorn.Config(create_app(s, loaded="single:0"), host="127.0.0.1", port=port,
                                           log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        _check_explorer(browser.new_page(), f"http://127.0.0.1:{port}/ui")
    finally:
        server.should_exit = True

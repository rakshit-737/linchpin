"""Regenerate docs/img/ui.png from the static demo with Playwright (python scripts/screenshot.py).

Serves docs/demo/ on localhost, loads the real-export case study, keeps the top remediation
selected (its evidence paths highlighted) and zooms the graph to those paths so labels are
readable. Needs `pip install playwright && python -m playwright install chromium`.
"""
from __future__ import annotations

import functools
import http.server
import socket
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "docs" / "demo"
OUT = ROOT / "docs" / "img" / "ui.png"


def main() -> int:
    from playwright.sync_api import sync_playwright
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(DEMO))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1400, "height": 820}, color_scheme="light")
            page.goto(f"http://127.0.0.1:{port}/index.html")
            page.wait_for_selector("tr.rem[data-i]", timeout=30000)
            page.wait_for_timeout(1500)  # let the breadthfirst layout settle
            page.evaluate("""() => {
                // frame the hosts, credentials and data stores on the highlighted paths (the many
                // DMZ vulns fan out sideways and would shrink everything else)
                const hot = cy.nodes('.broken').filter(n => /^(internet|host|cred|ds|priv)/.test(n.id()));
                cy.fit(hot.length ? hot : cy.elements(), 40);
                cy.nodes().style({'font-size': 12, 'text-background-color': '#ffffff',
                                  'text-background-opacity': 0.8, 'text-background-padding': 1});
            }""")
            page.wait_for_timeout(500)
            page.screenshot(path=str(OUT), full_page=False)
            browser.close()
    finally:
        srv.shutdown()
    print(f"wrote {OUT} ({OUT.stat().st_size / 1e3:.0f} kB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

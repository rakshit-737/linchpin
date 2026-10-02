"""Snapshot the web UI into a static demo for GitHub Pages (docs/demo/).

    python scripts/build_static_demo.py [--data-dir ../../datasets/linchpin]

Writes docs/demo/index.html (the regular UI in static mode) and one JSON snapshot per
dataset: the four synthetic families (seed 0) and, when the public datasets are present,
the real-export case study. Snapshots hold only graph structure derived from public sample
exports; what-if is recomputed client-side over the enumerated paths.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from linchpin.api.app import STATIC, create_app  # noqa: E402

BUDGETS = range(1, 6)


def snapshot(client: TestClient) -> dict:
    g = client.get("/graph").json()
    return {
        "stats": client.get("/stats").json(),
        "graph": g,
        "chokepoints": client.get("/chokepoints").json(),
        "paths": client.get("/paths", params={"k": 100}).json(),
        "remediations": {str(b): client.get("/remediations", params={"budget": b}).json() for b in BUDGETS},
        "nodes": {n["data"]["id"]: client.get(f"/nodes/{n['data']['id']}").json() for n in g["nodes"]},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=str(ROOT.parent.parent / "datasets" / "linchpin"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo"))
    a = ap.parse_args(argv)
    out = Path(a.out)
    (out / "data").mkdir(parents=True, exist_ok=True)
    # The API only reads the scenario the server is configured with (see api/app.py).
    os.environ["LINCHPIN_SCENARIO"] = str(ROOT / "scenarios" / "composite_lab.yaml")
    os.environ["LINCHPIN_DATA_DIR"] = str(Path(a.data_dir).resolve())
    client = TestClient(create_app(), base_url="http://127.0.0.1")
    for fam in ("single", "multi", "none", "ad"):
        client.post("/demo/load", json={"family": fam, "seed": 0}).raise_for_status()
        (out / "data" / f"{fam}.json").write_text(json.dumps(snapshot(client), separators=(",", ":")), "utf-8")
        print("wrote", fam)
    default = "single"
    if (Path(a.data_dir) / "derived" / "cve_intel.csv.gz").exists():
        r = client.post("/demo/load", json={"family": "scenario"})
        r.raise_for_status()
        (out / "data" / "case_study.json").write_text(json.dumps(snapshot(client), separators=(",", ":")), "utf-8")
        default = "case_study"
        print("wrote case_study")
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    inject = (f"<script>window.LINCHPIN_STATIC = 'data/'; window.LINCHPIN_STATIC_DEFAULT = '{default}';</script>\n"
              "<title>")
    html = html.replace("<title>", inject, 1).replace(
        '<option value="scenario">server scenario (LINCHPIN_SCENARIO)</option>',
        '<option value="scenario">real-export case study</option>')
    html = html.replace('<span class="stat" id="stats"></span>',
                        '<span class="stat" id="stats"></span><span class="stat">static demo: seed 0 only; '
                        'what-if counts the enumerated paths</span>')
    (out / "index.html").write_text(html, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

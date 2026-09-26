import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from linchpin.api.app import create_app  # noqa: E402
from linchpin.models import AttackPath, PathStats, Remediation  # noqa: E402
from linchpin.synth.generator import generate  # noqa: E402


def test_api_flow():
    client = TestClient(create_app())
    findings, gt = generate(15, 5, 2)
    body = [f.model_dump() for f in findings] + [{"garbage": True}]
    r = client.post("/ingest", json=body).json()
    assert r["accepted"] == len(findings) and r["rejected"] == 1
    assert client.post("/graph/build").json()["nodes"] > 0
    paths = client.get("/paths", params={"k": 5}).json()
    assert len(paths) == 5
    for p in paths:
        AttackPath.model_validate(p)
    rems = client.get("/remediations", params={"budget": 3}).json()
    assert Remediation.model_validate(rems[0]).target_node == gt.linchpin
    assert client.get(f"/nodes/{gt.linchpin}").json()["label"] == "Host"
    assert client.get("/nodes/nope").status_code == 404
    w = PathStats.model_validate(client.post("/whatif", json={"remove_nodes": [gt.linchpin]}).json())
    assert w.paths_after == 0


def test_ui_endpoints_and_demo_load():
    client = TestClient(create_app())
    st = client.post("/demo/load", json={"family": "multi", "seed": 1, "n_hosts": 14}).json()
    assert st["nodes"] > 0 and st["reachable_crown_jewels"]
    g = client.get("/graph").json()
    assert len(g["nodes"]) == st["nodes"] and len(g["edges"]) == st["edges"]
    ch = client.get("/chokepoints").json()
    assert ch["chokepoints"] == [] and ch["min_cut_size"] >= 2
    assert client.get("/criticality").status_code == 200
    ui = client.get("/ui")
    assert ui.status_code == 200 and "cytoscape" in ui.text
    assert client.post("/demo/load", json={"family": "bogus"}).status_code == 400

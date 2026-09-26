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

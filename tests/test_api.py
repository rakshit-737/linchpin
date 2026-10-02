import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from linchpin.api.app import create_app
from linchpin.models import AttackPath, PathStats, Remediation
from linchpin.synth.generator import generate

LOCAL = "http://127.0.0.1"  # the API only answers Host headers on its allow-list


def test_api_flow():
    client = TestClient(create_app(), base_url=LOCAL)
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


def test_abuse_limits(monkeypatch, tmp_path):
    monkeypatch.setenv("LINCHPIN_MAX_BODY_MB", "0.01")  # ~10 KB
    monkeypatch.delenv("LINCHPIN_SCENARIO", raising=False)
    monkeypatch.delenv("LINCHPIN_SCENARIO_DIR", raising=False)
    client = TestClient(create_app(), base_url=LOCAL)
    big = [{"pad": "x" * 1000}] * 50
    assert client.post("/ingest", json=big).status_code == 413
    assert client.get("/paths", params={"k": 10_001}).status_code == 422
    assert client.get("/remediations", params={"budget": 0}).status_code == 422
    assert client.get("/remediations", params={"budget": 51}).status_code == 422
    assert client.post("/whatif", json={"remove_nodes": ["x"] * 1001}).status_code == 422
    outside = tmp_path / "evil.yaml"
    outside.write_text("name: x\n")
    r = client.post("/demo/load", json={"family": "scenario", "scenario": str(outside)})
    assert r.status_code == 403
    assert client.post("/demo/load", json={"family": "scenario"}).status_code == 400  # none configured
    monkeypatch.setenv("LINCHPIN_SCENARIO_DIR", str(tmp_path))
    # only names relative to LINCHPIN_SCENARIO_DIR: absolute, UNC, drive and '..' paths are refused by text
    for bad in (str(outside), r"\\attacker.example\share\x.yaml", "//attacker.example/share/x.yaml",
                "C:evil.yaml", "../evil.yaml", "sub/../../evil.yaml", "evil.yaml:stream", "NUL"):
        assert client.post("/demo/load", json={"family": "scenario", "scenario": bad}).status_code == 403, bad
    ok = client.post("/demo/load", json={"family": "scenario", "scenario": "evil.yaml"})
    assert ok.status_code == 200 and ok.json()["loaded"] == "scenario:x"


def test_body_limit_without_content_length(monkeypatch):
    """Chunked upload with no Content-Length header is cut off once it passes the limit."""
    import asyncio
    monkeypatch.setenv("LINCHPIN_MAX_BODY_MB", "0.001")  # ~1 KB
    app = create_app()
    chunks = [b"[" + b"0," * 400, b"0," * 400, b"0]"]
    sent: list[dict] = []

    async def receive():
        body = chunks.pop(0) if chunks else b""
        return {"type": "http.request", "body": body, "more_body": bool(chunks)}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
             "scheme": "http", "path": "/ingest", "raw_path": b"/ingest", "query_string": b"",
             "root_path": "", "headers": [(b"host", b"127.0.0.1"), (b"content-type", b"application/json")],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8000)}
    asyncio.run(app(scope, receive, send))
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 413


def test_ui_endpoints_and_demo_load():
    client = TestClient(create_app(), base_url=LOCAL)
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


def test_paths_from_parameter_matches_frozen_contract():
    from pathlib import Path

    import yaml
    client = TestClient(create_app(), base_url=LOCAL)
    client.post("/demo/load", json={"family": "single", "seed": 0, "n_hosts": 12})
    frozen = yaml.safe_load((Path(__file__).parents[1] / "contracts" / "openapi.yaml").read_text())
    live = client.get("/openapi.json").json()["paths"]
    for path, ops in frozen["paths"].items():
        for method, op in ops.items():
            want = {p["name"] for p in op.get("parameters", [])}
            have = {p["name"] for p in live[path][method].get("parameters", [])}
            assert want <= have, (path, method, want - have)
    web = "host:web-00"
    got = client.get("/paths", params={"from": web, "k": 3}).json()
    assert got and all(p["nodes"][0] == web for p in got)
    assert client.get("/paths", params={"from": "web-00", "k": 3}).json()[0]["nodes"][0] == web  # bare host name
    assert client.get("/paths", params={"frm": web, "k": 3}).json()[0]["nodes"][0] == web  # old spelling
    assert client.get("/paths", params={"k": 3}).json()[0]["nodes"][0] == "internet"


def test_host_header_allow_list(monkeypatch):
    client = TestClient(create_app(), base_url=LOCAL)
    assert client.get("/stats", headers={"host": "attacker.example:8000"}).status_code == 400
    assert client.get("/stats", headers={"host": "attacker.example"}).status_code == 400
    for ok in ("127.0.0.1:8000", "localhost:8000", "[::1]:8000", "localhost"):
        assert client.get("/stats", headers={"host": ok}).status_code == 200, ok
    monkeypatch.setenv("LINCHPIN_ALLOWED_HOSTS", "lab.internal")
    other = TestClient(create_app(), base_url="http://lab.internal")
    assert other.get("/stats").status_code == 200
    assert other.get("/stats", headers={"host": "127.0.0.1"}).status_code == 400


def test_unbuildable_details_are_rejected_not_crashing():
    client = TestClient(create_app(), base_url=LOCAL)
    bad = [{"finding_id": "x1", "host_id": "h1", "kind": "credential", "source": "probe",
            "observed_at": "2026-01-01T00:00:00Z", "detail": {}},
           {"finding_id": "x2", "host_id": "net", "kind": "reachability", "source": "probe",
            "observed_at": "2026-01-01T00:00:00Z", "detail": {"from_segment": "a", "ports": ["22"]}}]
    r = client.post("/ingest", json=bad).json()
    assert r["accepted"] == 0 and r["rejected"] == 2 and r["rejected_reasons"]
    assert client.post("/graph/build").status_code == 200


def test_build_and_store_size_limits(monkeypatch):
    monkeypatch.setenv("LINCHPIN_MAX_EDGES", "50")
    client = TestClient(create_app(), base_url=LOCAL)
    assert client.post("/demo/load", json={"family": "none", "seed": 0, "n_hosts": 30}).status_code == 413
    findings, _ = generate(15, 5, 2)
    assert client.post("/ingest", json=[f.model_dump() for f in findings]).status_code == 200
    r = client.post("/graph/build")
    assert r.status_code == 413 and "edges" in r.json()["detail"]
    monkeypatch.setenv("LINCHPIN_MAX_FINDINGS", "10")
    more, _ = generate(15, 5, 3)
    assert client.post("/ingest", json=[f.model_dump() for f in more]).status_code == 413


def test_scenario_file_references_stay_in_the_data_dir(monkeypatch, tmp_path):
    scen, data = tmp_path / "scen", tmp_path / "data"
    scen.mkdir()
    data.mkdir()
    (tmp_path / "secret.xml").write_text("<nmaprun></nmaprun>")
    (scen / "escape.yaml").write_text("name: escape\nsources: [../secret.xml]\n")
    (scen / "absolute.yaml").write_text(f"name: abs\nsources: ['{(tmp_path / 'secret.xml').as_posix()}']\n")
    monkeypatch.setenv("LINCHPIN_SCENARIO_DIR", str(scen))
    monkeypatch.setenv("LINCHPIN_DATA_DIR", str(data))
    client = TestClient(create_app(), base_url=LOCAL)
    for name in ("escape.yaml", "absolute.yaml"):
        r = client.post("/demo/load", json={"family": "scenario", "scenario": name})
        assert r.status_code == 403, (name, r.text)


def test_interactive_docs_are_opt_in(monkeypatch):
    client = TestClient(create_app(), base_url=LOCAL)
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 200
    monkeypatch.setenv("LINCHPIN_API_DOCS", "1")
    assert TestClient(create_app(), base_url=LOCAL).get("/docs").status_code == 200

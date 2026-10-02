import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from linchpin.models import NormalizedFinding, make_finding_id
from linchpin.synth.generator import generate

ROOT = Path(__file__).resolve().parents[1]


def test_contract_files_exist():
    for f in ["finding.schema.json", "graph_model.md", "openapi.yaml", "edge_cost.md", "config.schema.json"]:
        assert (ROOT / "contracts" / f).exists()


def test_schema_and_model_agree():
    schema = json.loads((ROOT / "contracts" / "finding.schema.json").read_text())
    kinds = {"cve", "service", "credential", "acl", "config", "reachability"}
    assert set(schema["properties"]["kind"]["enum"]) == kinds
    assert set(schema["required"]) <= set(NormalizedFinding.model_fields)
    assert set(schema["properties"]) == set(NormalizedFinding.model_fields)


def test_finding_id_stable():
    assert make_finding_id("h", "cve", "k") == make_finding_id("h", "cve", "k")
    assert len(make_finding_id("h", "cve", "k")) == 16


@pytest.mark.parametrize("bad", [{"cve_id": "CVE-XX"}, {"cvss_base": 11}, {"epss": 1.5}, {"kind": "nope"}])
def test_invalid_findings_rejected(bad):
    base = dict(finding_id="x", host_id="h", kind="cve", source="t", observed_at="2026-01-01T00:00:00Z")
    with pytest.raises(ValidationError):
        NormalizedFinding(**{**base, **bad})


def test_synth_is_schema_valid_and_deterministic():
    a, gta = generate(15, 5, 7)
    b, gtb = generate(15, 5, 7)
    assert [x.model_dump() for x in a] == [x.model_dump() for x in b]
    assert gta == gtb
    for f in a:
        NormalizedFinding.model_validate(f.model_dump())

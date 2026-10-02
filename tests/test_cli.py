import json

from linchpin.cli import main


def run(capsys, *argv):
    rc = main(list(argv))
    return rc, capsys.readouterr().out


def test_cli_flow(tmp_path, capsys):
    st = str(tmp_path / "state.json")
    data = str(tmp_path / "synth.json")
    base = ["--state", st, "--config", str(tmp_path / "none.yaml")]
    rc, out = run(capsys, *base, "synth", "--out", data, "--seed", "3")
    assert rc == 0 and json.loads(out)["ground_truth"]["linchpin"] == "host:jump-01"
    rc, out = run(capsys, *base, "ingest", data)
    assert rc == 0 and json.loads(out)["accepted"] > 0
    rc, out = run(capsys, *base, "build")
    assert rc == 0 and json.loads(out)["nodes"] > 0
    rc, out = run(capsys, *base, "paths", "--k", "3")
    paths = json.loads(out)
    assert rc == 0 and len(paths) == 3 and {"path_id", "nodes", "total_cost"} <= set(paths[0])
    rc, out = run(capsys, *base, "fix", "--budget", "2")
    assert rc == 0 and json.loads(out)[0]["target_node"] == "host:jump-01"
    rc, out = run(capsys, *base, "whatif", "--remove", "jump-01")
    assert rc == 0 and json.loads(out)["paths_after"] == 0
    rc, _ = run(capsys, *base, "node", "does-not-exist")
    assert rc == 2


def test_cli_version_help_and_friendly_errors(tmp_path, capsys):
    import pytest

    from linchpin import __version__
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and __version__ in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        main(["serve", "--help"])
    assert e.value.code == 0 and "127.0.0.1" in capsys.readouterr().out
    base = ["--state", str(tmp_path / "s.json")]
    for argv, msg in ((["fix"], "no findings ingested yet"),
                      (["ingest", str(tmp_path / "missing.xml")], "no such file or directory"),
                      (["scenario", str(tmp_path / "missing.yaml")], "no such file"),
                      (["fix", "--budget", "0"], None)):
        with pytest.raises(SystemExit) as e:
            main(base + argv)
        if msg:
            assert msg in str(e.value.code)
        else:  # argparse validation error
            assert e.value.code == 2


def test_cli_real_exports_scenario_cuts_export(tmp_path, capsys):
    from pathlib import Path
    fix = Path(__file__).parent / "fixtures"
    st = str(tmp_path / "state.json")
    base = ["--state", st, "--config", str(tmp_path / "none.yaml")]
    rc, out = run(capsys, *base, "ingest", "--replace", str(fix / "openvas_sample.xml"),
                  str(fix / "nessus_sample.nessus"), str(fix / "bloodhound"))
    got = json.loads(out)
    assert rc == 0 and got["accepted"] > 20 and not got["skipped"]
    rc, out = run(capsys, *base, "scenario", str(fix / "scenario_mini.yaml"))
    assert rc == 0 and json.loads(out)["name"] == "mini"
    rc, out = run(capsys, *base, "cuts")
    cuts = json.loads(out)
    assert rc == 0 and "cred:ADMINISTRATOR@TESTLAB.LOCAL" in cuts["chokepoints"]
    rc, out = run(capsys, *base, "fix", "--budget", "1")
    assert rc == 0 and json.loads(out)[0]["residual_paths"] == 0
    for fmt in ("cypher", "graphml"):
        dest = tmp_path / f"g.{fmt}"
        rc, _ = run(capsys, *base, "export", "--format", fmt, "--out", str(dest))
        assert rc == 0 and dest.stat().st_size > 1000


def test_cli_ingest_applies_topology_aliases(tmp_path, capsys):
    """`ingest exports... topology.yaml` must merge scanner hosts onto the topology ids like `scenario` does."""
    from pathlib import Path
    fix = Path(__file__).parent / "fixtures"
    exports = [str(fix / "openvas_sample.xml"), str(fix / "nmap_vulners.xml"), str(fix / "bloodhound")]
    a = ["--state", str(tmp_path / "a" / "s.json"), "--config", str(tmp_path / "none.yaml")]
    rc, out = run(capsys, *a, "ingest", "--replace", *exports, str(fix / "scenario_mini.yaml"))
    got = json.loads(out)
    assert rc == 0 and got["aliases"] == 2 and got["unmatched_aliases"] == []
    assert got["graph"]["reachable_crown_jewels"]
    rc, out = run(capsys, *a, "fix", "--budget", "3")
    plan_ingest = [r["target_node"] for r in json.loads(out)]
    b = ["--state", str(tmp_path / "b" / "s.json"), "--config", str(tmp_path / "none.yaml")]
    run(capsys, *b, "scenario", str(fix / "scenario_mini.yaml"))
    rc, out = run(capsys, *b, "fix", "--budget", "3")
    assert plan_ingest and plan_ingest == [r["target_node"] for r in json.loads(out)]

    # a typo under match: is reported, and an unreachable crown jewel is explained instead of a silent []
    topo = tmp_path / "topo.yaml"
    topo.write_text((fix / "scenario_mini.yaml").read_text().replace("b6b9f466d63", "typo-host"))
    c = ["--state", str(tmp_path / "c" / "s.json"), "--config", str(tmp_path / "none.yaml")]
    assert main([*c, "ingest", "--replace", *exports, str(topo)]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["unmatched_aliases"] == ["typo-host"]
    assert "matches no host id" in captured.err


def test_cli_synth_families_use_real_cves(tmp_path, capsys):
    out_file = tmp_path / "s.json"
    rc, out = run(capsys, "synth", "--family", "ad", "--hosts", "12", "--out", str(out_file))
    assert rc == 0 and json.loads(out)["ground_truth"]["cve_pool"].startswith("sha256:")
    cves = [f["cve_id"] for f in json.loads(out_file.read_text()) if f["kind"] == "cve"]
    assert cves and not any(c.startswith("CVE-2099-") for c in cves)
    rc, _ = run(capsys, "synth", "--family", "legacy", "--hosts", "12", "--out", str(out_file))
    legacy = {f["cve_id"] for f in json.loads(out_file.read_text()) if f["kind"] == "cve"}
    assert {c for c in legacy if not c.startswith("CVE-2099-")} == {"CVE-2021-44228"}  # the labelled decoy only


def test_cli_reference_page_is_generated_from_the_parser():
    import subprocess
    import sys
    from pathlib import Path
    script = Path(__file__).parents[1] / "scripts" / "gen_cli_reference.py"
    r = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

"""SharpHound / BloodHound CE JSON (v5/v6 ingest format) -> identity-layer findings.

Pass the path of ``computers.json`` (or a directory holding the collection); sibling
``users.json`` / ``groups.json`` / ``domains.json`` are loaded from the same directory.
Only the attacker-relevant subset is modelled:

* local ``Administrators`` membership (nested groups expanded)   -> ``acl`` AdminTo
* ``Remote Desktop Users`` / ``Remote Management Users``          -> ``acl`` CanRDP / CanPSRemote
* Domain Admins / Enterprise Admins / Administrators members      -> AdminTo every computer
* interactive / privileged / registry sessions                    -> ``credential`` cached on
  that computer (``cred_type=hash``), ``valid_on`` = hosts the user administers
* each computer                                                   -> ``config`` inventory
  (segment ``ad``; domain controllers flagged and given an ``ntds`` datastore)

ACE-based edges (GenericAll, WriteDacl, DCSync, ADCS ...) are out of scope; see docs/.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from linchpin.connectors._common import epoch_iso, finding
from linchpin.models import NormalizedFinding

SOURCE = "bloodhound"
PRIV_RIDS = ("-512", "-519", "-544")  # Domain Admins, Enterprise Admins, BUILTIN\Administrators
LOCAL_GROUP_RIGHT = {"-544": "AdminTo", "-555": "CanRDP", "-580": "CanPSRemote"}


def _load(d: Path, name: str) -> list[dict]:
    p = d / f"{name}.json"
    if not p.exists():
        cands = sorted(d.glob(f"*_{name}.json"))
        if not cands:
            return []
        p = cands[0]
    return json.loads(p.read_text(encoding="utf-8-sig")).get("data", [])


def is_bloodhound(path: str | Path) -> bool:
    p = Path(path)
    if p.is_dir():
        return (p / "computers.json").exists() or any(p.glob("*_computers.json"))
    if p.suffix.lower() != ".json":
        return False
    head = p.read_text(encoding="utf-8-sig", errors="ignore")[:200000]
    return '"meta"' in head and '"methods"' in head


def host_name(computer_name: str) -> str:
    return computer_name.lower()


def parse(path: str) -> list[NormalizedFinding]:
    p = Path(path)
    d = p if p.is_dir() else p.parent
    if p.is_file() and not (p.stem == "computers" or p.stem.endswith("_computers")):
        return []  # consumed together with computers.json
    computers, users, groups = _load(d, "computers"), _load(d, "users"), _load(d, "groups")
    observed = epoch_iso(None)

    names: dict[str, str] = {}
    enabled: dict[str, bool] = {}
    for obj in users + computers + groups:
        sid = obj["ObjectIdentifier"]
        names[sid] = obj.get("Properties", {}).get("name") or sid
        enabled[sid] = obj.get("Properties", {}).get("enabled", True) is not False
    members: dict[str, list[tuple[str, str]]] = {
        g["ObjectIdentifier"]: [(m["ObjectIdentifier"], m.get("ObjectType", "")) for m in g.get("Members", [])]
        for g in groups}
    user_sids = {u["ObjectIdentifier"] for u in users}

    def expand(sid: str, typ: str, seen: set[str] | None = None) -> set[str]:
        seen = seen or set()
        if sid in seen:
            return set()
        seen.add(sid)
        if typ == "User" or sid in user_sids:
            return {sid} if enabled.get(sid, True) else set()
        out: set[str] = set()
        for m, t in members.get(sid, []):
            out |= expand(m, t, seen)
        return out

    domain_admins: set[str] = set()
    for gsid in members:
        if gsid.endswith(PRIV_RIDS):
            domain_admins |= expand(gsid, "Group")

    hosts = {c["ObjectIdentifier"]: host_name(names[c["ObjectIdentifier"]]) for c in computers}
    rights: dict[tuple[str, str], set[str]] = defaultdict(set)  # (user_sid, right) -> host ids
    for c in computers:
        hid = hosts[c["ObjectIdentifier"]]
        for lg in c.get("LocalGroups", []) or []:
            right = next((r for rid, r in LOCAL_GROUP_RIGHT.items()
                          if lg.get("ObjectIdentifier", "").endswith(rid)), None)
            if not right:
                continue
            for m in lg.get("Results", []):
                for u in expand(m["ObjectIdentifier"], m.get("ObjectType", "")):
                    rights[(u, right)].add(hid)
        for u in domain_admins:
            rights[(u, "AdminTo")].add(hid)

    out: list[NormalizedFinding] = []
    for c in computers:
        sid = c["ObjectIdentifier"]
        props = c.get("Properties", {})
        is_dc = bool(c.get("IsDC") or props.get("isdc"))
        out.append(finding(hosts[sid], "config", "inventory", SOURCE, observed, detail={
            "issue": "inventory", "severity": "low", "segment": "ad", "os": props.get("operatingsystem"),
            "internet_facing": False, "is_dc": is_dc, "sid": sid,
            "datastores": [{"name": f"ntds@{hosts[sid]}", "sensitivity": "high"}] if is_dc else []}))
    for (u, right), targets in sorted(rights.items()):
        for t in sorted(targets):
            out.append(finding("identity", "acl", f"{u}|{right}|{t}", SOURCE, observed, detail={
                "principal": names.get(u, u), "right": right, "target": t, "sid": u}))
    sessions: dict[str, set[str]] = defaultdict(set)
    for c in computers:
        for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            for s in (c.get(key) or {}).get("Results", []) or []:
                if s.get("UserSID") in user_sids:
                    sessions[hosts[c["ObjectIdentifier"]]].add(s["UserSID"])
    for s in _load(d, "sessions"):  # legacy standalone session collection
        if s.get("ComputerSID") in hosts and s.get("UserSID") in user_sids:
            sessions[hosts[s["ComputerSID"]]].add(s["UserSID"])
    for hid, sids in sorted(sessions.items()):
        for u in sorted(sids):
            if not enabled.get(u, True):
                continue
            out.append(finding(hid, "credential", names.get(u, u), SOURCE, observed, detail={
                "principal": names.get(u, u), "cred_type": "hash", "sid": u,
                "valid_on": sorted(rights.get((u, "AdminTo"), set())),
                "domain_admin": u in domain_admins}))
    return out

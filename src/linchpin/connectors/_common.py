"""Shared helpers for connectors: safe XML parsing, CVSS-vector classification, finding builders."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import parse as _safe_parse

from linchpin.models import NormalizedFinding, make_finding_id

if TYPE_CHECKING:  # the stdlib parser is imported for the type annotation only, never to parse
    from xml.etree.ElementTree import Element  # nosec B405

EPOCH0 = "1970-01-01T00:00:00+00:00"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def parse_xml(path: str | Path) -> Element:
    """Parse an exported XML report with defusedxml (a hard dependency; there is no fallback).

    Raises:
        ValueError: the document declares entities or references external resources
            (XXE, billion laughs); callers report the file as skipped.
    """
    try:
        return _safe_parse(str(path)).getroot()
    except DefusedXmlException as e:
        raise ValueError(f"{path}: refused unsafe XML ({type(e).__name__})") from None


def epoch_iso(s: str | int | None) -> str:
    """ISO-8601 UTC timestamp for a Unix epoch (the epoch itself when missing or invalid)."""
    try:
        return datetime.fromtimestamp(int(s), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return EPOCH0


def impact_class(vector: str | None) -> str | None:
    """Classify what exploiting a vuln gives the attacker, from its CVSS vector.

    rce   -- network/adjacent reachable AND high integrity impact (v3 I:H, v2 I:C or C:P/I:P/A:P)
    local -- requires local/physical access (privilege escalation once on the box)
    info  -- anything else (disclosure / DoS / partial integrity) => no privilege gained
    None  -- no vector known (callers treat this conservatively as `rce`)
    """
    if not vector:
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    av = parts.get("AV")
    if av in ("L", "P"):
        return "local"
    integ = parts.get("I")
    if integ in ("H", "C"):
        return "rce"
    # CVSS v2 "C:P/I:P/A:P" is NVD's typical scoring for code execution as an unprivileged
    # service account (e.g. PHP-CGI CVE-2012-1823) -- treat it as a foothold too.
    if "Au" in parts and (parts.get("C"), integ, parts.get("A")) == ("P", "P", "P"):
        return "rce"
    return "info"


_RCE_HINT = re.compile(r"backdoor|code execution|command execution|command injection|default credential|"
                       r"remote shell|arbitrary code|unauthenticated access|brute force login|rexec|rlogin|rsh ",
                       re.I)


def guess_impact(vector: str | None, name: str | None, severity: float | None) -> str:
    """impact_class from the vector when present, else a conservative name/severity heuristic."""
    cls = impact_class(vector)
    if cls is not None:
        return cls
    if _RCE_HINT.search(name or "") or (severity or 0) >= 9.0:
        return "rce"
    return "info"


def clean(s: str | None) -> str | None:
    """Collapse runs of whitespace in report text."""
    return " ".join(s.split()) if s else s


def finding(host_id: str, kind: str, key: str, source: str, observed_at: str, **kw) -> NormalizedFinding:
    """Build a :class:`NormalizedFinding` with its stable id ``sha256(host|kind|key)[:16]``."""
    return NormalizedFinding(finding_id=make_finding_id(host_id, kind, key), host_id=host_id, kind=kind,
                             source=source, observed_at=observed_at, **kw)


def rep_cve(cves: list[str]) -> str | None:
    """Deterministic representative CVE for a multi-CVE plugin/NVT (newest id first)."""
    if not cves:
        return None
    return sorted(set(cves), key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])), reverse=True)[0]

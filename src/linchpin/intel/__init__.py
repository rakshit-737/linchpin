"""Real-world exploitability intelligence: NVD CVSS, FIRST EPSS and CISA KEV.

`CveIntel` is a read-only lookup table built once from the downloaded public feeds
(`python -m linchpin intel-build`) and cached as a gzipped CSV. Connectors and the
edge-cost model consume it through :func:`linchpin.intel.enrich.enrich`.
"""
from linchpin.intel.store import CveIntel, CveRecord

__all__ = ["CveIntel", "CveRecord"]

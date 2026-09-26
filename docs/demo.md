# Live demo

The [path explorer](demo/index.html) runs entirely in your browser from pre-computed JSON snapshots
(`scripts/build_static_demo.py`). No server, no data leaves the page.

* **real-export case study** (default): public OpenVAS / Nessus / nmap / SharpHound sample exports with a declared topology, see [Benchmarks](benchmarks.md#real-export-case-study).
* **single / multi / none / ad**: the four synthetic benchmark families, seed 0.

Click a remediation to highlight every attack path it breaks. Click Vuln, Credential, Ace or Host nodes to
toggle them off; the what-if panel recomputes reachability of the crown jewels in the browser and counts the
enumerated paths (k = 100) that survive. The full server (`uvicorn linchpin.api.app:app`) re-enumerates paths
instead and accepts any seed.

[Open the demo](demo/index.html){ .md-button .md-button--primary }

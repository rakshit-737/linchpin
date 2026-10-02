# Live demo

The [path explorer](demo/index.html) runs entirely in your browser from pre-computed JSON snapshots
(`scripts/build_static_demo.py`). No server, and no data leaves the page.

* **real-export case study** (default): public OpenVAS / Nessus / nmap / SharpHound sample exports with a declared
  topology, see [Evaluation](evaluation.md#real-export-case-study-declared-topology).
* **single / multi / none / ad**: the four synthetic benchmark families, seed 0.

Click a remediation to highlight every attack path it breaks; pick a crown jewel to see only the paths that end there.
Click Vuln, Credential, Ace or Host nodes to toggle them off: the what-if panel recomputes reachability of the crown
jewels in the browser and shows the enumerated paths (k = 100) before and after. The static demo holds snapshots for
seed 0 and budgets 1-10; the full server (`linchpin serve`) re-enumerates paths and accepts any seed.

[Open the demo](demo/index.html){ .md-button .md-button--primary }

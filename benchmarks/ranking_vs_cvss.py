"""Usage: python benchmarks/ranking_vs_cvss.py [n_topologies] [budget]"""
import json
import sys

from linchpin.benchmark import run

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    b = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    print(json.dumps(run(n, b), indent=2))

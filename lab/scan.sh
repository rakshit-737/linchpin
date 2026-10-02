#!/usr/bin/env bash
# Service/version detection of the CI lab, from one scanner container inside each internal network.
#
#   nmap -sV -sT -Pn -n: TCP connect + version probes only. No --script, -sC or -A (no NSE at all),
#   no OS detection, no exploitation. Targets are the IPs of the lab containers on that network,
#   read from `docker network inspect`; nothing else is ever addressed.
#
# Output (OUT, default artifacts/lab): scan-lp-dmz.xml, scan-lp-core.xml, networks.json, versions.txt
set -euo pipefail
OUT="${OUT:-artifacts/lab}"
mkdir -p "$OUT"
chmod 0777 "$OUT"   # the scanner runs as an unprivileged user inside its container
docker network inspect lp-dmz lp-core > "$OUT/networks.json"

targets() {  # container IPs on network $1
  docker network inspect "$1" -f '{{range .Containers}}{{.IPv4Address}} {{end}}' | sed 's#/[0-9]*##g'
}

# wait (at most ~3 min) until every lab service answers on its default port
declare -A WANT=([lp-dmz]="80,8080" [lp-core]="3306,6379,8080")
for net in lp-dmz lp-core; do
  for i in $(seq 1 36); do
    open=$(docker run --rm --network "$net" lp-scanner -sT -Pn -n -p "${WANT[$net]}" --open -oG - $(targets "$net") \
           | grep -o '[0-9]*/open' | wc -l)
    need=$(( $(echo "${WANT[$net]}" | tr ',' '\n' | wc -l) ))
    [ "$open" -ge "$need" ] && break
    sleep 5
  done
done

for net in lp-dmz lp-core; do
  docker run --rm --network "$net" -v "$(realpath "$OUT"):/out" lp-scanner \
    -sV -sT -Pn -n -T4 --version-intensity 7 -p 1-10000 -oX "/out/scan-$net.xml" $(targets "$net")
done

# the scans must contain service versions only: fail if any NSE script output slipped in
if grep -q "<script " "$OUT"/scan-*.xml; then echo "NSE script output found in the scans" >&2; exit 1; fi
docker run --rm lp-scanner --version | head -1 > "$OUT/versions.txt"
docker version --format 'docker {{.Server.Version}}' >> "$OUT/versions.txt"
grep -ho 'product="[^"]*" version="[^"]*"' "$OUT"/scan-*.xml | sort -u

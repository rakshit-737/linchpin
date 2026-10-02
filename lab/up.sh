#!/usr/bin/env bash
# CI lab for the measured case study (run only inside an ephemeral GitHub Actions runner).
#
# Starts official Docker images pinned to older releases with published CVEs, attached ONLY to
# Docker networks created with --internal (no route to the internet or to the runner's other
# networks). Nothing is exploited and nothing outside these containers is ever contacted:
# lab/scan.sh performs TCP service/version detection only (nmap -sV, no NSE scripts).
#
#   lp-dmz  (internal): web (httpd 2.4.49), proxy (nginx 1.16.1), app (tomcat 9.0.30)
#   lp-core (internal): app (dual-homed: the only DMZ -> core path), cache (redis 5.0.7), db (mysql 5.5.62)
set -euo pipefail
cd "$(dirname "$0")"

docker network create --internal lp-dmz
docker network create --internal lp-core

docker run -d --name web   --network lp-dmz  httpd:2.4.49
docker run -d --name proxy --network lp-dmz  nginx:1.16.1
docker run -d --name app   --network lp-dmz  tomcat:9.0.30
docker network connect lp-core app
docker run -d --name cache --network lp-core redis:5.0.7
# a random root password is generated inside the container and never leaves it
docker run -d --name db    --network lp-core -e MYSQL_RANDOM_ROOT_PASSWORD=yes mysql:5.5.62

# scanner image: Debian's nmap package, nothing else
docker build -q -t lp-scanner -f Dockerfile.scanner .
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'

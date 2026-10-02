#!/usr/bin/env bash
# Remove the CI lab containers and networks (the runner is discarded afterwards anyway).
docker rm -f web proxy app cache db >/dev/null 2>&1 || true
docker network rm lp-dmz lp-core >/dev/null 2>&1 || true

# ADR 0005: A static, dependency-free path explorer instead of React + Vite

**Status:** accepted (v1.0, recorded in v1.1)

## Context
The spec's M10 asks for a React + Vite + TypeScript path explorer with TanStack Query, Recharts and component tests.
The explorer needs: a Cytoscape.js graph, the remediation table with evidence highlighting, a crown-jewel filter, and
a what-if panel with a before/after comparison. It must also run as a static demo on GitHub Pages without a server.

## Decision
One HTML file (`src/linchpin/api/static/index.html`, about 14 kB) with plain JavaScript and Cytoscape.js loaded from
jsDelivr pinned by version with a Subresource-Integrity hash. It talks to the API with `fetch`; in static mode
(`window.LINCHPIN_STATIC`, injected by `scripts/build_static_demo.py`) the same code reads pre-computed JSON snapshots
and recomputes what-if reachability in the browser. The before/after comparison is drawn as two CSS bars instead of a
charting library.

## Consequences
- No build step, no `node_modules`, nothing to keep patched beyond one pinned script; the wheel ships the UI as
  package data and the GitHub Pages demo is the same file.
- Instead of component tests, Playwright smoke tests drive both the live API and the *built* static site in CI:
  remediation selection, crown-jewel filter, what-if bars, disabled seed input and budgets 1-10 in static mode.
- A richer UI (routing, larger state) would justify revisiting React; the current scope does not.

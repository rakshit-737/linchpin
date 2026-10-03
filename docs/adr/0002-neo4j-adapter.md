# ADR 0002: Neo4j as a mirror (and GDS for path search), not the computation engine

**Status:** accepted (v0.2); GDS backend added in v1.1

## Context
The spec puts the attack graph in Neo4j and suggests GDS for path queries. The engines (Yen, dominators, max-flow,
greedy what-if) are implemented on NetworkX and tested against ground truth. GDS has no min-cut and no dominators, and
requiring a server would break "tests pass without infrastructure".

## Decision
`Neo4jGraphStore` builds the graph with the same code as the in-memory store, so costs are identical. It mirrors the
graph into Neo4j with idempotent, batched `UNWIND ... MERGE` using the frozen labels and relationship types. `pull()`
reads a graph back so every engine runs unchanged on data held in Neo4j. `to_cypher()` renders the same statements as
a script for offline use (parameters substituted in a single pass, so scanned strings cannot break it). Graphs are
namespaced by a `graph` property.

With the Graph Data Science plugin, `gds_project()` and `gds_k_shortest_paths()` run Yen's algorithm inside Neo4j
(`gds.shortestPath.yens`) over the same `cost` property and map the result back to `AttackPath` with the same path ids.
`connect()` verifies connectivity, and only an "unknown function" error counts as "GDS not installed".

## Consequences
- Neo4j Browser/Bloom exploration and custom Cypher work on the real attack graph.
- Unit tests use an in-memory fake driver. CI runs a live round trip against `neo4j:5.26-community`, and a GDS job
  (GDS 2.13.13) cross-checks Yen on graphs of 60k and 239k relationships: identical costs and path sets, Yen
  1.4-39x faster inside Neo4j (medians across four CI runs), but the mirror takes 5-23 s, more than the NetworkX
  computation it replaces. GDS pays off only
  when the graph already lives in Neo4j. The job fails when the plugin is missing.
- The official image's entrypoint fetches the GDS jar from Neo4j's plugin host at start-up.

# ADR 0002: Neo4j as a mirror, not the computation engine

**Status:** accepted (v0.2)

## Context
The spec puts the attack graph in Neo4j and suggests GDS for path queries. The engines (Yen, dominators, max-flow, greedy what-if) are already implemented on NetworkX and tested against ground truth. GDS has no min-cut and no dominators, and requiring a server would break "tests pass without infrastructure".

## Decision
`Neo4jGraphStore` builds the graph with the same code as the in-memory store, so costs are identical. It then mirrors the graph into Neo4j with idempotent, batched `UNWIND ... MERGE` using the frozen labels and relationship types. `pull()` reads a graph back so every engine runs unchanged on data held in Neo4j. `to_cypher()` renders the same statements as a script for offline use. Graphs are namespaced by a `graph` property, so several scenarios can coexist.

## Consequences
- Neo4j Browser/Bloom exploration and custom Cypher work on the real attack graph.
- Unit tests use an in-memory fake driver. A CI job runs a live round trip against a `neo4j:5` service container.
- GDS-native path search for very large graphs remains future work.

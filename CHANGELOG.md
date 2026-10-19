# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **SIMD bitmatrix engine** over MITRE ATT&CK (enterprise, ICS, mobile) crossed
  with MITRE D3FEND and the CISA Known Exploited Vulnerabilities catalog,
  flattened into a frozen set of structure-of-arrays bitmatrix planes. Every
  directed relation is materialized in both directions, so a traversal is one
  row fetch plus vector bitwise ops — no pointer chasing, no per-edge
  allocation and no strings on the hot path.
- **Seven node partitions**: techniques (TTPs, sub-techniques included),
  artifacts, countermeasures, data components, grouping nodes (actors,
  software, campaigns), KEV entries, and the weakness and product vocabularies
  the catalog names.
- **`cmd/gr4ph` lookup CLI** with fourteen commands — `ttp`, `artifact`, `cm`,
  `dc`, `group`, `tactic`, `platform`, `kev`, `cwe`, `product`, `rel`,
  `coverage`, `gain` and `contain` — plus `help`. Every relation of a resolved
  node is printed in both directions; `-rel`, `-defrel` and `-family` narrow a
  set to one plane, and `-json` emits one object per resolved query.
- **Coverage overlay**: `coverage`, `gain` and `contain` classify every
  technique as defended, undefended, retired or unmapped, and rank
  countermeasures by the live technique surface they newly cover.
- **Vulnerability queries**: the KEV → CWE matrix (1689 references over 189
  weaknesses) and the KEV → product matrix (exactly one edge per entry, over
  726 products), with `kev`, `cwe` and `product` resolving each direction.
- **Two committed table generators**, `cmd/d3fendgen` and `cmd/kevgen`, which
  regenerate `ontology/attack_gen.go` and `ontology/kev_gen.go` from the pinned
  upstream sources.

### Notes

- **Release requirements**: Go 1.27 with `GOEXPERIMENT=simd` exported for
  build, vet and test — every library file carries `//go:build goexperiment.simd`.
- **Standard library only**: zero third-party dependencies and no `go.sum`.
- **Offline at runtime**: the pinned ATT&CK 19.2 (enterprise, ICS, mobile) ×
  D3FEND 1.6.0 × CISA KEV 2026.10.16 tables are generated and committed; the
  runtime never touches the network. Only `make gen` needs it.
- **Measured shape** (pinned sources): 1186 techniques, 247 artifacts, 157
  countermeasures, 123 data components, 1212 grouping nodes, 1748 KEV entries,
  189 weaknesses, 726 products, 41 tactics and 15 platforms — 609,075 words
  (4.647 MiB) across the twenty-one frozen arrays.
- **Zero allocation** on the hot path, enforced by `AllocsPerRun` tests, plus a
  `-race` pass over concurrent queries of the immutable engine.
- **License**: Apache-2.0 — see [LICENSE](LICENSE). The MITRE ATT&CK/D3FEND,
  The Aerospace Corporation SPARTA and CISA KEV notices are in
  [NOTICE](NOTICE).

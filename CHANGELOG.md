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
- **Vulnerability queries**: the KEV → CWE matrix (a reference per weakness
  class an entry is filed under) and the KEV → product matrix (exactly one edge
  per entry, `NProduct` collapsed vendor/product keys), with `kev`, `cwe` and
  `product` resolving each direction.
- **Two committed table generators**, `cmd/d3fendgen` and `cmd/kevgen`, which
  regenerate `ontology/attack_gen.go` and `ontology/kev_gen.go` from the pinned
  upstream sources.

### Notes

- **Release requirements**: Go 1.27 with `GOEXPERIMENT=simd` exported for
  build, vet and test — every library file carries `//go:build goexperiment.simd`.
- **Standard library only**: zero third-party dependencies and no `go.sum`.
- **Offline at runtime**: the tables pinned by the `ontology.Source*` constants
  are generated and committed; the runtime never touches the network. Only
  `make gen` needs it.
- **Sizes are the generated constants**: every node, predicate and vocabulary
  count lives in `ontology` (`NTTP`, `NArtifact`, `NCountermeasure`, `NKEV`,
  `NCWE`, `NProduct`, …) and the README's memory table is written as formulas
  over them, so a KEV catalog roll needs no prose or test edit; a versioned
  ATT&CK/D3FEND bump moves the literal release counts with it.
  `GOEXPERIMENT=simd go doc -all ./ontology` prints the current values.
- **Zero allocation** on the hot path, enforced by `AllocsPerRun` tests, plus a
  `-race` pass over concurrent queries of the immutable engine.
- **License**: Apache-2.0 — see [LICENSE](LICENSE). The MITRE ATT&CK/D3FEND,
  The Aerospace Corporation SPARTA and CISA KEV notices are in
  [NOTICE](NOTICE).

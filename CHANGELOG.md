# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.1] - 2026-10-19

### Changed

- **The pinned dataset is the CISA KEV catalog of 2026-10-23.** `make gen`
  re-pinned `known_exploited_vulnerabilities.json@2026.10.23` in place — the
  generator's own `sourceKEV` and `pinnedShape` plus `ontology/kev_gen.go`, a
  two-file diff with no hand edits — adding eight entries and the weakness and
  product references that came with them. No code, API, CLI text or prose
  changed: the tests and the README sizes derive from the generated constants,
  and `make all`/`make stock` pass unedited. The ATT&CK 19.2 × D3FEND 1.6.0
  release pins are untouched, so a consumer on `v0.2.0` sees the older catalog
  until it moves.

## [0.2.0] - 2026-10-19

### Fixed

- **A KEV catalog roll re-pins itself**: `cmd/kevgen` rewrites its own
  `pinnedShape` acknowledgement and `ontology/kev_gen.go`, so `make gen` after a
  CISA revision leaves a two-file diff and needs no hand edits. A count change
  under an unchanged `catalogVersion` is now an error instead of a silent
  rewrite, and a malformed catalog date is rejected at parse time.
- **`ontology.Register` validates the emitted array lengths** before indexing
  them, returning `ontology: <family>: array lengths …, want …` instead of
  panicking part-way through registration on a short table.
- **The KEV expectations are derived, not quoted**: the ontology, CLI and
  benchmark tests compute every KEV count, stride, class and union from the
  generated constants and the engine; the synthetic fixture keeps its own
  constants. The README and this changelog state formulas over `ontology.N*`
  instead of the counts the pinned catalog happened to carry.
- **Documentation corrections**: `GOEXPERIMENT=simd go doc -all ./ontology`
  prints every generated count (the plain `go doc` form elides all but the
  first constant of each group), and the re-pin notes scope "edits nothing
  else" to a KEV catalog roll — a versioned ATT&CK/D3FEND bump moves its
  release URLs, `pinnedShape`, the literal counts in the ontology tests and the
  numbers the README quotes together.

## [0.1.0] - 2026-10-14

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
- **Zero allocation** on the hot path, enforced by `AllocsPerRun` tests, plus a
  `-race` pass over concurrent queries of the immutable engine.
- **License**: Apache-2.0 — see [LICENSE](LICENSE). The MITRE ATT&CK/D3FEND,
  The Aerospace Corporation SPARTA and CISA KEV notices are in
  [NOTICE](NOTICE).

//go:build goexperiment.simd

// Package gr4ph is a SIMD bitmatrix engine over MITRE ATT&CK (enterprise, ICS,
// mobile) and D3FEND.
//
// It flattens seven node partitions — techniques (TTPs, including every
// sub-technique), artifacts, countermeasures, data components (DC), grouping
// nodes (actors G, software S, campaigns C), KEV entries (CVE ids) and the
// weakness and product vocabularies the catalog names — into a frozen set of
// structure-of-arrays bitmatrix planes, plus the per-technique ATT&CK attribute
// masks (tactics, platforms, sub-technique flag). Every directed relation is
// materialized in both directions, so a traversal is a row fetch plus vector
// bitwise ops: no pointer chasing, no per-edge allocation, no strings on the
// hot path.
//
// # Build requirement
//
// The engine is built on Go 1.27's experimental simd package, whose files are
// all gated behind the goexperiment.simd build tag. Every file in this module
// (except cmd/d3fendgen, cmd/kevgen, internal/simdcheck, internal/hotmethods
// and internal/atomicfile) carries the same tag, so a stock build fails with
// the explicit constraint error rather than undefined-symbol noise;
// internal/simdcheck makes that true for ./... too, which would otherwise skip
// every gated package and report success:
//
//	GOEXPERIMENT=simd go build ./...
//
// The Makefile exports GOEXPERIMENT=simd for every target except `stock`, which
// unsets it deliberately (see internal/simdcheck).
//
// # Hot path vs cold path
//
// Hot-path methods take and return only uint16-derived ids (TTP, Artifact,
// Countermeasure, DataComponent, Group, KEV, CWE, Product) or one-word attribute
// masks, and never allocate: callers supply dst slices for results and a scratch
// row for set/roll-up operations. Strings appear only in the cold path —
// building the graph, and formatting ids back into log lines (Incident, TTPName,
// TTPLabel, Response, ...).
//
// # Relations
//
// Two many-predicate families carry one plane per predicate plus plane 0 as the
// union of all of them (RelAny / DefRelAny):
//
//	ttpArt / artTTP   technique -> artifact        (offensive, Rel)
//	cmArt  / artCM    countermeasure -> artifact   (defensive, DefRel)
//
// The remaining families are single inferred predicates, so they need no plane
// index:
//
//	cmTTP  / ttpCM         countermeasure -> technique   (defends-against)
//	tacticTTP / ttpTactic  tactic -> technique           (assignment; mask per technique)
//	platformTTP / ttpPlatform  platform -> technique      (assignment; mask per technique)
//	dcTTP  / ttpDC         data component -> technique   (detects)
//	grpTTP / ttpGrp        grouping node -> technique    (uses)
//	grpSoftware / softwareGrp  grouping node -> software (uses)
//	kevCWE / cweKEV        KEV entry -> weakness         (the catalog's cwes)
//	kevProduct / productKEV  KEV entry -> product        (the entry's vendor/product)
//
// ttpFlags is the per-technique attribute column; Build derives the
// sub-technique bit from the hierarchy, so it cannot disagree with it.
//
// # Roll-up
//
// The ATT&CK hierarchy is carried as data (parent index + child count), never
// baked into the matrices, so callers choose precision explicitly: the exact
// methods (Artifacts, TTPs, CountermeasuresForTTP, DataComponentsForTTP, ...)
// follow edges only, while the *Rollup variants expand a parent onto its direct
// children or collapse sub-techniques onto their parent.
//
// # Panics
//
// Every hot-path query is total over the id space of a built engine: an id
// outside its partition answers 0/false instead of panicking, so a stale or
// foreign id set can never crash a traversal. (The zero Engine is not a built
// engine: it has no plane 0, so a relation-taking query panics there — see
// Engine.) Three classes of misuse have no sensible fallback and panic
// instead:
//
//   - an id outside its partition passed to a cold accessor (TTPName, TTPLabel,
//     GroupKind, GroupRevoked, TTPRevoked, KEVRansomware, ...), or a relation id
//     outside RelCount()+1 (offensive) / DefRelCount()+1 (defensive);
//   - a scratch row shorter than WordsPerRow of the partition the query returns
//     ("gr4ph: scratch too small"), or a selection shorter than WordsPerRow of
//     the partition it indexes ("gr4ph: selection too small");
//   - a Kind that WordsPerRow does not map ("gr4ph: unknown kind").
//
// Response and CountermeasureResponse are the total boundary formatters: they
// render "<invalid ttp N>" / "<invalid cm N>" and still count the entry.
//
// See README.md for the full API, the memory layout and the two end-to-end
// flows (defensive triage and authorized offensive planning).
package gr4ph

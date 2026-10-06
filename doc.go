//go:build goexperiment.simd

// Package gr4ph is a SIMD bitmatrix engine over MITRE ATT&CK (enterprise, ICS,
// mobile) and D3FEND.
//
// It flattens three node partitions — techniques (TTPs, including every
// sub-technique), artifacts and countermeasures — into a frozen set of
// structure-of-arrays bitmatrix planes. Every directed relation is materialised
// in both directions, so a traversal is a row fetch plus vector bitwise ops:
// no pointer chasing, no per-edge allocation, no strings on the hot path.
//
// # Build requirement
//
// The engine is built on Go 1.27's experimental simd package, whose files are
// all gated behind the goexperiment.simd build tag. Every file in this module
// (except cmd/d3fendgen) carries the same tag, so a stock build fails with the
// explicit constraint error rather than undefined-symbol noise:
//
//	GOEXPERIMENT=simd go build ./...
//
// The Makefile exports GOEXPERIMENT=simd for every target.
//
// # Hot path vs cold path
//
// Hot-path methods take and return only uint16-derived ids (TTP, Artifact,
// Countermeasure) and never allocate: callers supply dst slices for results and
// a scratch row for set/roll-up operations. Strings appear only in the cold
// path — building the graph, and formatting ids back into log lines
// (Incident, TTPName, TTPLabel, Response, ...).
//
// # Relations
//
// Two many-predicate families carry one plane per predicate plus plane 0 as the
// union of all of them (RelAny / DefRelAny):
//
//	ttpArt / artTTP   technique -> artifact        (offensive, Rel)
//	cmArt  / artCM    countermeasure -> artifact   (defensive, DefRel)
//
// The countermeasure -> technique link is a single inferred predicate
// (defends-against), so it needs no plane index:
//
//	cmTTP  / ttpCM     countermeasure -> technique
//
// # Roll-up
//
// The ATT&CK hierarchy is carried as data (parent index + child count), never
// baked into the matrices, so callers choose precision explicitly: the exact
// methods (Artifacts, TTPs, CountermeasuresForTTP, ...) follow edges only,
// while the *Rollup variants expand a parent onto its direct children or
// collapse sub-techniques onto their parent.
//
// See README.md for the full API, the memory layout and the two end-to-end
// flows (defensive triage and authorized offensive planning).
package gr4ph

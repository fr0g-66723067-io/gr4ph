//go:build goexperiment.simd

package gr4ph

// --- hot path: offensive traversals ---

// Adjacent reports whether technique t is linked to artifact a under any
// relation.
func (e *Engine) Adjacent(t TTP, a Artifact) bool { return e.AdjacentRel(t, a, RelAny) }

// AdjacentRel reports whether t -> a holds under relation r (RelAny for the
// union plane).
// It panics if r is out of range.
func (e *Engine) AdjacentRel(t TTP, a Artifact, r Rel) bool {
	e.checkRel(r)
	if !e.okTTP(t) || !e.okArt(a) {
		return false
	}
	return testBit(e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt), int(a))
}

// Artifacts writes the artifacts linked to t under any relation into dst,
// truncated to len(dst), and returns the total number of matches.
func (e *Engine) Artifacts(t TTP, dst []Artifact) int { return e.ArtifactsRel(t, RelAny, dst) }

// ArtifactsRel is Artifacts restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range.
func (e *Engine) ArtifactsRel(t TTP, r Rel, dst []Artifact) int {
	e.checkRel(r)
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt), dst)
}

// TTPs writes the techniques linked to a under any relation into dst,
// truncated to len(dst), and returns the total number of matches.
func (e *Engine) TTPs(a Artifact, dst []TTP) int { return e.TTPsRel(a, RelAny, dst) }

// TTPsRel is TTPs restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range.
func (e *Engine) TTPsRel(a Artifact, r Rel, dst []TTP) int {
	e.checkRel(r)
	if !e.okArt(a) {
		return 0
	}
	return enumerate(e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP), dst)
}

// Degree returns the number of artifacts linked from t under r.
// It panics if r is out of range.
func (e *Engine) Degree(t TTP, r Rel) int {
	e.checkRel(r)
	if !e.okTTP(t) {
		return 0
	}
	return popcountRow(e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
}

// ArtifactDegree returns the number of techniques linked to a under r.
// It panics if r is out of range.
func (e *Engine) ArtifactDegree(a Artifact, r Rel) int {
	e.checkRel(r)
	if !e.okArt(a) {
		return 0
	}
	return popcountRow(e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
}

// --- hot path: set operations over artifact / technique slices ---

// TTPsAny writes the union of the technique rows of arts under r. Ids outside
// the artifact partition are ignored; an empty (or all-invalid) input yields 0.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsAny(r Rel, scratch []uint64, dst []TTP, arts []Artifact) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	for _, a := range arts {
		if !e.okArt(a) {
			continue
		}
		orRowInto(row, e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
	}
	return enumerate(row, dst)
}

// TTPsAll writes the intersection of the technique rows of arts under r.
// Invalid ids are ignored; if none remain the result is empty.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsAll(r Rel, scratch []uint64, dst []TTP, arts []Artifact) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	first := true
	for _, a := range arts {
		if !e.okArt(a) {
			continue
		}
		if first {
			copyRow(row, e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
			first = false
			continue
		}
		andRowInto(row, e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
	}
	return enumerate(row, dst)
}

// ArtifactsAny writes the union of the artifact rows of ttps under r.
// Ids outside the technique partition are ignored; an empty (or all-invalid)
// input yields 0.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range or len(scratch) < WordsPerRow(KindArtifact).
func (e *Engine) ArtifactsAny(r Rel, scratch []uint64, dst []Artifact, ttps []TTP) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindArtifact)
	row := scratch[:e.wArt]
	clear(row)
	for _, t := range ttps {
		if !e.okTTP(t) {
			continue
		}
		orRowInto(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
	}
	return enumerate(row, dst)
}

// ArtifactsAll writes the intersection of the artifact rows of ttps under r.
// Ids outside the technique partition are ignored; an empty (or all-invalid)
// input yields 0.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range or len(scratch) < WordsPerRow(KindArtifact).
func (e *Engine) ArtifactsAll(r Rel, scratch []uint64, dst []Artifact, ttps []TTP) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindArtifact)
	row := scratch[:e.wArt]
	clear(row)
	first := true
	for _, t := range ttps {
		if !e.okTTP(t) {
			continue
		}
		if first {
			copyRow(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
			first = false
			continue
		}
		andRowInto(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
	}
	return enumerate(row, dst)
}

// --- hot path: roll-up over the technique hierarchy ---

// ArtifactsRollup writes the union of the artifact rows of t and all its
// direct sub-techniques under any relation. For a sub-technique this is
// exactly its own row (the hierarchy is two levels deep).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsRollup(t TTP, scratch []uint64, dst []Artifact) int {
	return e.ArtifactsRollupRel(t, RelAny, scratch, dst)
}

// ArtifactsRollupRel is ArtifactsRollup restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range or len(scratch) < WordsPerRow(KindArtifact).
func (e *Engine) ArtifactsRollupRel(t TTP, r Rel, scratch []uint64, dst []Artifact) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindArtifact)
	if !e.okTTP(t) {
		return 0
	}
	row := scratch[:e.wArt]
	copyRow(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
	for c := int(t) + 1; c <= int(t)+int(e.ttpChildCount[t]); c++ {
		orRowInto(row, e.row(e.ttpArt, e.ttpArtOff(r, TTP(c)), e.wArt))
	}
	return enumerate(row, dst)
}

// TTPsRollup writes the techniques linked to a under any relation, with every
// sub-technique collapsed onto its parent.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsRollup(a Artifact, scratch []uint64, dst []TTP) int {
	return e.TTPsRollupRel(a, RelAny, scratch, dst)
}

// TTPsRollupRel is TTPsRollup restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if r is out of range or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsRollupRel(a Artifact, r Rel, scratch []uint64, dst []TTP) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindTTP)
	if !e.okArt(a) {
		return 0
	}
	row := scratch[:e.wTTP]
	clear(row)
	eachBit(e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP), func(x int) bool {
		if p := e.ttpParents[x]; p != uint16(NoParent) {
			setBit(row, int(p))
		} else {
			setBit(row, x)
		}
		return true
	})
	return enumerate(row, dst)
}

// --- hot path: countermeasure queries ---

// Defends reports whether countermeasure cm defends technique t.
func (e *Engine) Defends(cm Countermeasure, t TTP) bool {
	if !e.okCM(cm) || !e.okTTP(t) {
		return false
	}
	return testBit(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP), int(t))
}

// CountermeasuresForTTP writes the countermeasures defending exactly t.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CountermeasuresForTTP(t TTP, dst []Countermeasure) int {
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpCM, e.ttpCMOff(t), e.wCM), dst)
}

// CountermeasuresForTTPRollup writes the union of the countermeasures
// defending t and all its direct sub-techniques.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(scratch) < WordsPerRow(KindCountermeasure).
func (e *Engine) CountermeasuresForTTPRollup(t TTP, scratch []uint64, dst []Countermeasure) int {
	e.checkScratch(scratch, KindCountermeasure)
	if !e.okTTP(t) {
		return 0
	}
	row := scratch[:e.wCM]
	copyRow(row, e.row(e.ttpCM, e.ttpCMOff(t), e.wCM))
	for c := int(t) + 1; c <= int(t)+int(e.ttpChildCount[t]); c++ {
		orRowInto(row, e.row(e.ttpCM, e.ttpCMOff(TTP(c)), e.wCM))
	}
	return enumerate(row, dst)
}

// CountermeasuresForArtifact writes the countermeasures directly linked to a
// under defensive relation dr (DefRelAny for the union plane).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if dr is out of range.
func (e *Engine) CountermeasuresForArtifact(a Artifact, dr DefRel, dst []Countermeasure) int {
	e.checkDefRel(dr)
	if !e.okArt(a) {
		return 0
	}
	return enumerate(e.row(e.artCM, e.artCMOff(dr, a), e.wCM), dst)
}

// CountermeasuresForArtifactViaTTPs writes the countermeasure surface of a:
// the countermeasures directly linked to a, unioned with the countermeasures
// defending every technique that touches a. Techniques are used exactly as
// linked (no hierarchy roll-up) — see the package documentation.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(scratch) < WordsPerRow(KindCountermeasure).
func (e *Engine) CountermeasuresForArtifactViaTTPs(a Artifact, scratch []uint64, dst []Countermeasure) int {
	e.checkScratch(scratch, KindCountermeasure)
	if !e.okArt(a) {
		return 0
	}
	row := scratch[:e.wCM]
	clear(row)
	eachBit(e.row(e.artTTP, e.artTTPOff(RelAny, a), e.wTTP), func(t int) bool {
		orRowInto(row, e.row(e.ttpCM, e.ttpCMOff(TTP(t)), e.wCM))
		return true
	})
	eachBit(e.row(e.artCM, e.artCMOff(DefRelAny, a), e.wCM), func(cm int) bool {
		setBit(row, cm)
		return true
	})
	return enumerate(row, dst)
}

// ArtifactsForCountermeasure writes the artifacts linked from cm under
// defensive relation dr (DefRelAny for the union plane).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if dr is out of range.
func (e *Engine) ArtifactsForCountermeasure(cm Countermeasure, dr DefRel, dst []Artifact) int {
	e.checkDefRel(dr)
	if !e.okCM(cm) {
		return 0
	}
	return enumerate(e.row(e.cmArt, e.cmArtOff(dr, cm), e.wArt), dst)
}

// TTPsForCountermeasure writes the techniques defended by cm, exactly as
// linked (sub-technique ids included).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForCountermeasure(cm Countermeasure, dst []TTP) int {
	if !e.okCM(cm) {
		return 0
	}
	return enumerate(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP), dst)
}

// TTPsForCountermeasureRollup is TTPsForCountermeasure with every
// sub-technique collapsed onto its parent.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsForCountermeasureRollup(cm Countermeasure, scratch []uint64, dst []TTP) int {
	e.checkScratch(scratch, KindTTP)
	if !e.okCM(cm) {
		return 0
	}
	row := scratch[:e.wTTP]
	clear(row)
	eachBit(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP), func(t int) bool {
		if p := e.ttpParents[t]; p != uint16(NoParent) {
			setBit(row, int(p))
		} else {
			setBit(row, t)
		}
		return true
	})
	return enumerate(row, dst)
}

// CountermeasureDegree returns the number of techniques defended by cm.
func (e *Engine) CountermeasureDegree(cm Countermeasure) int {
	if !e.okCM(cm) {
		return 0
	}
	return popcountRow(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP))
}

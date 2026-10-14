//go:build goexperiment.simd

package gr4ph

import "math/bits"

// --- hot path: coverage overlay (mask-driven) ---

// TTPsMapped writes the techniques with at least one defends-against edge — the
// range of the D3FEND mapping, i.e. the set the coverage states are measured
// against — and returns the total. It is the union of every cmTTP row, computed
// per call rather than stored: the union is derivable and the engine keeps no
// duplicate of a derivable row.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsMapped(scratch []uint64, dst []TTP) int {
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	for cm := range e.nCM {
		orRowInto(row, e.row(e.cmTTP, e.cmTTPOff(Countermeasure(cm)), e.wTTP))
	}
	return enumerate(row, dst)
}

// TTPsCovered writes the techniques defended by any countermeasure the
// selection names: the union of the selected cmTTP rows. A selection bit past
// the live countermeasure range selects no row, so a stale inventory cannot
// fail.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(sel) < WordsPerRow(KindCountermeasure) or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsCovered(sel Selection, scratch []uint64, dst []TTP) int {
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	return enumerate(row, dst)
}

// TTPsBlind writes the techniques that are active and not covered: active &^
// covered, i.e. the blind spots of a deployed set. Both selections are
// caller-owned; active is over techniques, sel over countermeasures. active is
// a selection like any other, so a bit past the technique range selects nothing
// rather than inventing an id.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(active) < WordsPerRow(KindTTP), len(sel) < WordsPerRow(KindCountermeasure)
// or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsBlind(active Selection, sel Selection, scratch []uint64, dst []TTP) int {
	e.checkSelection(active, KindTTP)
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	// row is now the covered set; mask it out of the active set. A row kernel
	// cannot do this in place — the operation reads two different slices — so
	// the loop is the whole computation.
	for i := range row {
		row[i] = active[i] &^ row[i]
	}
	// The active side is the only direct-enumeration path in the overlay, so it
	// is the one that must mask its own tail: the covered side is a selection
	// walked through orSelectedRowsInto, which ignores a row past the block.
	maskTail(row, e.nTTP)
	return enumerate(row, dst)
}

// CoverageGain returns how many techniques cm would newly cover on top of the
// deployed selection: popcount(cmTTP[cm] &^ covered(sel)) over the live
// techniques. It is the marginal value of adding one countermeasure, the number
// a procurement ranking sorts by. A retired technique is never a purchase
// target, so the flagged ones are masked out of the count. An out-of-range cm
// yields 0.
// It panics if len(sel) < WordsPerRow(KindCountermeasure) or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) CoverageGain(cm Countermeasure, sel Selection, scratch []uint64) int {
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	if !e.okCM(cm) {
		return 0
	}
	n := 0
	for i, w := range e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP) {
		n += bits.OnesCount64(w &^ row[i] &^ e.ttpRevokedRow[i])
	}
	return n
}

// CoverageGains writes the marginal gain of every countermeasure against one
// deployment: dst[cm] is what cm would newly cover on top of covered(sel), the
// number CoverageGain returns for a single candidate. The covered union is
// computed once for the whole scan, so ranking every countermeasure costs one
// selected-row union instead of one union per candidate. Retired techniques are
// masked out exactly as in CoverageGain, so a candidate is never credited for
// one. Countermeasures at and beyond len(dst) are counted but not written; the
// return value is the number of countermeasures with a positive gain.
// It panics if len(sel) < WordsPerRow(KindCountermeasure) or len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) CoverageGains(sel Selection, scratch []uint64, dst []int) int {
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	n := 0
	for cm := range e.nCM {
		g := 0
		for i, w := range e.row(e.cmTTP, e.cmTTPOff(Countermeasure(cm)), e.wTTP) {
			g += bits.OnesCount64(w &^ row[i] &^ e.ttpRevokedRow[i])
		}
		if g > 0 {
			n++
		}
		if cm < len(dst) {
			dst[cm] = g
		}
	}
	return n
}

// CountermeasuresForObserved writes the countermeasures of any observed
// technique: the union of the selected ttpCM rows, i.e. the mitigation set for
// the current state of an intrusion. observed is over techniques.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(observed) < WordsPerRow(KindTTP) or len(scratch) <
// WordsPerRow(KindCountermeasure).
func (e *Engine) CountermeasuresForObserved(observed Selection, scratch []uint64, dst []Countermeasure) int {
	e.checkSelection(observed, KindTTP)
	e.checkScratch(scratch, KindCountermeasure)
	row := scratch[:e.wCM]
	clear(row)
	orSelectedRowsInto(row, observed, e.ttpCM, e.wCM)
	return enumerate(row, dst)
}

// --- hot path: attributes, data components and groups ---

// TTPTactics returns the tactic mask of t: bit i is TacticID(i). It is 0 for a
// technique with no ATT&CK tactic (the D3FEND-named nodes), for an
// out-of-range id, and on an engine that registered no tactics (the row would
// have no words). One word per technique, so the read is a single load.
func (e *Engine) TTPTactics(t TTP) uint64 {
	if !e.okTTP(t) || e.nTactic == 0 {
		return 0
	}
	return e.ttpTactic[e.ttpTacticOff(t)]
}

// TTPPlatforms returns the platform mask of t: bit i is PlatformName(i). It is 0
// for an out-of-range id and on an engine that registered no platforms.
func (e *Engine) TTPPlatforms(t TTP) uint64 {
	if !e.okTTP(t) || e.nPlatform == 0 {
		return 0
	}
	return e.ttpPlatform[e.ttpPlatformOff(t)]
}

// TTPFlags returns the attribute flags of t: FlagSubTechnique for a
// sub-technique, 0 for a top-level technique or an out-of-range id. Build
// derives the bit from the hierarchy.
func (e *Engine) TTPFlags(t TTP) uint64 {
	if !e.okTTP(t) {
		return 0
	}
	return e.ttpFlags[e.ttpFlagsOff(t)]
}

// TTPSubTechnique reports whether t is a sub-technique (TTPFlags bit
// FlagSubTechnique).
func (e *Engine) TTPSubTechnique(t TTP) bool {
	return e.TTPFlags(t)&FlagSubTechnique != 0
}

// TTPsForTactic writes the techniques of tactic ta.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForTactic(ta Tactic, dst []TTP) int {
	if !e.okTactic(ta) {
		return 0
	}
	return enumerate(e.row(e.tacticTTP, e.tacticTTPOff(ta), e.wTTP), dst)
}

// TTPsForPlatform writes the techniques that run on platform p.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForPlatform(p Platform, dst []TTP) int {
	if !e.okPlatform(p) {
		return 0
	}
	return enumerate(e.row(e.platformTTP, e.platformTTPOff(p), e.wTTP), dst)
}

// TTPsForDataComponent writes the techniques dc's log sources can detect.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForDataComponent(dc DataComponent, dst []TTP) int {
	if !e.okDC(dc) {
		return 0
	}
	return enumerate(e.row(e.dcTTP, e.dcTTPOff(dc), e.wTTP), dst)
}

// DataComponentsForTTP writes the data components that detect exactly t.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) DataComponentsForTTP(t TTP, dst []DataComponent) int {
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpDC, e.ttpDCOff(t), e.wDC), dst)
}

// DataComponentsForTTPRollup writes the union of the data components detecting
// t and all its direct sub-techniques: the ATT&CK detections hang off the
// sub-technique, so a parent's own row is usually empty.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(scratch) < WordsPerRow(KindDataComponent).
func (e *Engine) DataComponentsForTTPRollup(t TTP, scratch []uint64, dst []DataComponent) int {
	e.checkScratch(scratch, KindDataComponent)
	if !e.okTTP(t) {
		return 0
	}
	row := scratch[:e.wDC]
	copyRow(row, e.row(e.ttpDC, e.ttpDCOff(t), e.wDC))
	for c := int(t) + 1; c <= int(t)+int(e.ttpChildCount[t]); c++ {
		orRowInto(row, e.row(e.ttpDC, e.ttpDCOff(TTP(c)), e.wDC))
	}
	return enumerate(row, dst)
}

// DataComponentDegree returns the number of techniques dc can detect.
func (e *Engine) DataComponentDegree(dc DataComponent) int {
	if !e.okDC(dc) {
		return 0
	}
	return popcountRow(e.row(e.dcTTP, e.dcTTPOff(dc), e.wTTP))
}

// TTPsForGroup writes the techniques g is recorded as using, exactly as linked
// (sub-techniques stay sub-techniques).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForGroup(g Group, dst []TTP) int {
	if !e.okGroup(g) {
		return 0
	}
	return enumerate(e.row(e.grpTTP, e.grpTTPOff(g), e.wTTP), dst)
}

// TTPsForGroupRollup is TTPsForGroup with every sub-technique collapsed onto
// its parent.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(scratch) < WordsPerRow(KindTTP).
func (e *Engine) TTPsForGroupRollup(g Group, scratch []uint64, dst []TTP) int {
	e.checkScratch(scratch, KindTTP)
	if !e.okGroup(g) {
		return 0
	}
	row := scratch[:e.wTTP]
	clear(row)
	eachBit(e.row(e.grpTTP, e.grpTTPOff(g), e.wTTP), func(t int) bool {
		if p := e.ttpParents[t]; p != uint16(NoParent) {
			setBit(row, int(p))
		} else {
			setBit(row, t)
		}
		return true
	})
	return enumerate(row, dst)
}

// GroupsForTTP writes every grouping node — actor, software or campaign — that
// uses t. Filter with GroupKind on the results for one kind.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) GroupsForTTP(t TTP, dst []Group) int {
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpGrp, e.ttpGrpOff(t), e.wGrp), dst)
}

// SoftwareForGroup writes the software g uses (empty for a software node).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) SoftwareForGroup(g Group, dst []Group) int {
	if !e.okGroup(g) {
		return 0
	}
	return enumerate(e.row(e.grpSoftware, e.grpSoftwareOff(g), e.wGrp), dst)
}

// GroupsForSoftware writes the actors and campaigns recorded as using software
// node g (empty for an actor or campaign).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) GroupsForSoftware(g Group, dst []Group) int {
	if !e.okGroup(g) {
		return 0
	}
	return enumerate(e.row(e.softwareGrp, e.softwareGrpOff(g), e.wGrp), dst)
}

// SoftwareDegree returns the number of software nodes g uses.
func (e *Engine) SoftwareDegree(g Group) int {
	if !e.okGroup(g) {
		return 0
	}
	return popcountRow(e.row(e.grpSoftware, e.grpSoftwareOff(g), e.wGrp))
}

// --- hot path: KEV, weakness and product queries ---

// KEVCWEDegree returns the number of weaknesses entry k names (0 for an
// out-of-range id).
func (e *Engine) KEVCWEDegree(k KEV) int {
	if !e.okKEV(k) {
		return 0
	}
	return popcountRow(e.row(e.kevCWE, e.kevCWEOff(k), e.wCWE))
}

// CWEsForKEV writes the weaknesses entry k names.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CWEsForKEV(k KEV, dst []CWE) int {
	if !e.okKEV(k) {
		return 0
	}
	return enumerate(e.row(e.kevCWE, e.kevCWEOff(k), e.wCWE), dst)
}

// KEVsForCWE writes the entries naming weakness c.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) KEVsForCWE(c CWE, dst []KEV) int {
	if !e.okCWE(c) {
		return 0
	}
	return enumerate(e.row(e.cweKEV, e.cweKEVOff(c), e.wKEV), dst)
}

// ProductsForKEV writes the product of entry k: exactly one id for a catalog
// entry, none for an out-of-range id.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ProductsForKEV(k KEV, dst []Product) int {
	if !e.okKEV(k) {
		return 0
	}
	return enumerate(e.row(e.kevProduct, e.kevProductOff(k), e.wProduct), dst)
}

// KEVsForProducts writes the union of the selected productKEV rows: the entries
// that apply to any of the products an asset inventory names. sel is over
// products; a bit past the live range selects no row.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(sel) < WordsPerRow(KindProduct) or len(scratch) < WordsPerRow(KindKEV).
func (e *Engine) KEVsForProducts(sel Selection, scratch []uint64, dst []KEV) int {
	e.checkSelection(sel, KindProduct)
	e.checkScratch(scratch, KindKEV)
	row := scratch[:e.wKEV]
	clear(row)
	orSelectedRowsInto(row, sel, e.productKEV, e.wKEV)
	return enumerate(row, dst)
}

// KEVsForCWEs writes the union of the selected cweKEV rows: the entries in any
// of the named weakness classes. sel is over weaknesses.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
// It panics if len(sel) < WordsPerRow(KindCWE) or len(scratch) < WordsPerRow(KindKEV).
func (e *Engine) KEVsForCWEs(sel Selection, scratch []uint64, dst []KEV) int {
	e.checkSelection(sel, KindCWE)
	e.checkScratch(scratch, KindKEV)
	row := scratch[:e.wKEV]
	clear(row)
	orSelectedRowsInto(row, sel, e.cweKEV, e.wKEV)
	return enumerate(row, dst)
}

// enumerate writes the set bits of row into dst as ascending ids of type T
// (truncated to len(dst)) and returns the total number of set bits.
func enumerate[T ~uint16](row []uint64, dst []T) int {
	n := 0
	eachBit(row, func(i int) bool {
		if n < len(dst) {
			dst[n] = T(i)
		}
		n++
		return true
	})
	return n
}

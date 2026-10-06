// Package hotmethods holds the canonical list of the engine's 29 hot-path
// methods, so the root and ontology zero-allocation tests can prove they cover
// the same set instead of each counting to 29 on its own.
package hotmethods

// Names is the canonical order of the hot-path methods: the exact traversals,
// the set operations, the roll-ups, the countermeasure queries, the hierarchy
// accessors and the relation name accessor. Both zero-allocation tests build
// their cases in this order and assert their case names equal it.
var Names = []string{
	"Adjacent",
	"AdjacentRel",
	"Artifacts",
	"ArtifactsRel",
	"TTPs",
	"TTPsRel",
	"Degree",
	"ArtifactDegree",
	"ArtifactsRollup",
	"ArtifactsRollupRel",
	"TTPsRollup",
	"TTPsRollupRel",
	"TTPsAny",
	"TTPsAll",
	"ArtifactsAny",
	"ArtifactsAll",
	"Defends",
	"CountermeasuresForTTP",
	"CountermeasuresForTTPRollup",
	"CountermeasuresForArtifact",
	"CountermeasuresForArtifactViaTTPs",
	"ArtifactsForCountermeasure",
	"TTPsForCountermeasure",
	"TTPsForCountermeasureRollup",
	"CountermeasureDegree",
	"TTPParent",
	"TTPChildCount",
	"TTPChildren",
	"RelName",
}

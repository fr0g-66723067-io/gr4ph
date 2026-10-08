// Package hotmethods holds the canonical list of the engine's 46 allocation-free
// query methods, so the root and ontology zero-allocation tests can prove they
// cover the same set instead of each counting to 46 on its own.
package hotmethods

// Names is the canonical order of the hot-path methods: the exact traversals,
// the set operations, the roll-ups, the countermeasure queries, the technique
// attributes, the data-component and grouping queries, the hierarchy accessors
// and the two relation name accessors. Both zero-allocation tests build their
// cases in this order and assert their case names equal it.
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
	"TTPTactics",
	"TTPPlatforms",
	"TTPFlags",
	"TTPSubTechnique",
	"TTPsForTactic",
	"TTPsForPlatform",
	"TTPsForDataComponent",
	"DataComponentsForTTP",
	"DataComponentsForTTPRollup",
	"DataComponentDegree",
	"TTPsForGroup",
	"TTPsForGroupRollup",
	"GroupsForTTP",
	"SoftwareForGroup",
	"GroupsForSoftware",
	"SoftwareDegree",
	"TTPParent",
	"TTPChildCount",
	"TTPChildren",
	"RelName",
	"DefRelName",
}

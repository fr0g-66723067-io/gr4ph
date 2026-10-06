# gr4ph — SIMD bitmatrix engine for MITRE ATT&CK x D3FEND.
#
# Every library file is gated behind `goexperiment.simd`, so GOEXPERIMENT=simd
# is required for build, vet and test. The generator (cmd/d3fendgen) is untagged
# so that it can regenerate the ontology tables on a stock toolchain.

export GOEXPERIMENT=simd

GO ?= go

.PHONY: all vet test gen bench fmt clean stock

all: vet test

vet:
	$(GO) vet ./...

test:
	$(GO) vet ./...
	$(GO) test ./...

# Regenerates ontology/attack_gen.go from the pinned upstream sources (network).
gen:
	$(GO) run ./cmd/d3fendgen -out ontology/attack_gen.go

bench:
	$(GO) test -bench . -benchmem ./...

# Verifies the stock-toolchain contract: the generator builds and tests without
# the experiment, and the module as a whole fails loudly (internal/simdcheck)
# instead of silently skipping the gated packages.
stock:
	env -u GOEXPERIMENT $(GO) test ./cmd/d3fendgen
	env -u GOEXPERIMENT $(GO) build -o /dev/null ./cmd/d3fendgen
	! env -u GOEXPERIMENT $(GO) build ./...

fmt:
	$(GO) fmt ./...

clean:
	$(GO) clean -testcache

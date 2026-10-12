# gr4ph — SIMD bitmatrix engine for MITRE ATT&CK x D3FEND.
#
# Every library file is gated behind `goexperiment.simd` (only `cmd/d3fendgen`,
# `internal/simdcheck` and `internal/hotmethods` are outside the tag), so
# GOEXPERIMENT=simd is required for build, vet and test. The generator
# (cmd/d3fendgen) is untagged so that it can regenerate the ontology tables on a
# stock toolchain.

export GOEXPERIMENT=simd

GO ?= go
BIN ?= gr4ph

.PHONY: all build vet test gen bench fmt clean stock

all: vet test

# Builds the lookup CLI (cmd/gr4ph) into ./gr4ph. The command carries the
# library's build tag, so it needs the experiment exported above, exactly like
# the library; the stock-toolchain failure is pinned by `make stock`.
build:
	$(GO) build -o $(BIN) ./cmd/gr4ph

vet:
	$(GO) vet ./...

# The emulated pass is not redundant: with GODEBUG=simd=0 the simd package
# reports len(s) from LoadUint64sPart instead of min(lanes, len(s)), so it is the
# only pass that can catch a row kernel that advances by that count. Do not add
# GODEBUG=simd=256: on a CPU feature-reduced to 128 bits it panics at init
# ("larger than the simd length required for expected features"), and +256
# bypasses the CPU feature check, which can SIGILL.
test:
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -race ./...          # README "Concurrency": concurrent queries share the engine
	GODEBUG=simd=0 $(GO) test ./...

# Regenerates ontology/attack_gen.go and ontology/kev_gen.go from the pinned
# upstream sources (network): the ATT&CK 19.2 x D3FEND 1.6.0 release and the
# CISA Known Exploited Vulnerabilities catalog.
gen:
	$(GO) run ./cmd/d3fendgen -out ontology/attack_gen.go
	$(GO) run ./cmd/kevgen -out ontology/kev_gen.go

bench:
	$(GO) test -bench . -benchmem ./...

# Verifies the stock-toolchain contract: the generators build and test without
# the experiment, and the module as a whole fails loudly (internal/simdcheck)
# instead of silently skipping the gated packages.
stock:
	env -u GOEXPERIMENT $(GO) test ./cmd/d3fendgen
	env -u GOEXPERIMENT $(GO) build -o /dev/null ./cmd/d3fendgen
	env -u GOEXPERIMENT $(GO) test ./cmd/kevgen
	env -u GOEXPERIMENT $(GO) build -o /dev/null ./cmd/kevgen
	! env -u GOEXPERIMENT $(GO) build ./...

fmt:
	$(GO) fmt ./...

clean:
	$(GO) clean -testcache
	rm -f $(BIN)

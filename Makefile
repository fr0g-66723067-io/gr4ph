# gr4ph — SIMD bitmatrix engine for MITRE ATT&CK x D3FEND x CISA KEV.
#
# Every library file is gated behind `goexperiment.simd` (only the two
# generators `cmd/d3fendgen` and `cmd/kevgen`, `internal/simdcheck`,
# `internal/hotmethods`, `internal/atomicfile` and `internal/sourcefetch` are
# outside the tag), so GOEXPERIMENT=simd is required for build, vet and test.
# The generators and their atomicfile and sourcefetch helpers are untagged so
# that they can regenerate the ontology tables on a stock toolchain.

export GOEXPERIMENT=simd

GO ?= go
BIN ?= gr4ph
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS ?= -X main.version=$(VERSION)

# Every public repo publishes the same five targets and one SHA256SUMS.
RELEASE_TARGETS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
DIST ?= dist
RELEASE_LDFLAGS ?= -s -w $(LDFLAGS)

.PHONY: all build vet test gen bench fmt check clean stock release-gate release-binaries verify-release release

all: check vet test

# Builds the lookup CLI (cmd/gr4ph) into ./gr4ph. The command carries the
# library's build tag, so it needs the experiment exported above, exactly like
# the library; the stock-toolchain failure is pinned by `make stock`.
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/gr4ph

# The gate a tag must pass. The release workflow runs this before it builds
# anything, so a failing gate publishes nothing.
release-gate: all stock

release-binaries:
	rm -rf $(DIST)
	mkdir -p $(DIST)
	@set -e; for t in $(RELEASE_TARGETS); do \
	  goos=$${t%/*}; goarch=$${t#*/}; \
	  out=$(DIST)/$(BIN)_$(VERSION)_$${goos}_$${goarch}; \
	  [ "$$goos" = windows ] && out=$$out.exe; \
	  echo "  build $$out"; \
	  GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 $(GO) build -trimpath \
	    -ldflags "$(RELEASE_LDFLAGS)" -o $$out ./cmd/$(BIN); \
	done
	cd $(DIST) && sha256sum $(BIN)_* | sort -k2 > SHA256SUMS
	@echo "  $(DIST)/SHA256SUMS"

verify-release:
	sh tools/release/verify.sh $(DIST) $(VERSION)

release: release-binaries verify-release

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
	env -u GOEXPERIMENT $(GO) test ./internal/sourcefetch
	! env -u GOEXPERIMENT $(GO) build ./...

fmt:
	$(GO) fmt ./...

# Formatting as a gate rather than a fix: `fmt` rewrites the tree, so `all` and
# CI need a target that fails on an unformatted file instead of silently
# repairing it.
check:
	@test -z "$$(gofmt -l .)" || { echo "unformatted files (gofmt -l .):"; gofmt -l .; exit 1; }

clean:
	$(GO) clean -testcache
	rm -f $(BIN) d3fendgen kevgen
	rm -rf $(DIST)

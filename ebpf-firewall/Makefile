.PHONY: all userspace bpf clean verify install-deps phase1 phase2 phase3 phase4 generate-rules test help

# Linux-only datapath. On Windows, userspace Go is cross-compiled for linux/amd64.
ifeq ($(OS),Windows_NT)
  HOST_OS    := windows
  export GOOS   ?= linux
  export GOARCH ?= amd64
  export CGO_ENABLED ?= 0
else
  HOST_OS    := $(shell uname -s 2>/dev/null || echo unknown)
endif

CLANG      := clang
ARCH       := $(shell uname -m 2>/dev/null | sed 's/x86_64/x86/;s/aarch64/arm64/' || echo x86)
CFLAGS     := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(shell uname -m 2>/dev/null)-linux-gnu

P1_LOADER  := phase1/phase1-loader
P2_COLLECT := phase2/phase2-collector
P3_RULES   := phase3/phase3-rules-manager
P4_API     := phase4/phase4-api-server
P1_OBJ     := phase1/phase1_packet_filter.o
P2_OBJ     := phase2/phase2_ringbuf_events.o

all: userspace bpf
	@echo "All planned phases built (userspace always; BPF objects on Linux with clang)."

## ---- Userspace (all 4 phase binaries) ----
userspace: $(P1_LOADER) $(P2_COLLECT) $(P3_RULES) $(P4_API)
	@echo "Userspace binaries: $(P1_LOADER) $(P2_COLLECT) $(P3_RULES) $(P4_API) (GOOS=$${GOOS:-$$(go env GOOS)})"

## ---- BPF objects (Linux + clang) ----
bpf: $(P1_OBJ) $(P2_OBJ)

$(P1_OBJ): phase1/phase1_packet_filter.c
ifeq ($(HOST_OS),windows)
	@echo "Skip $(P1_OBJ): clang -target bpf requires Linux. Build this file on a 5.8+ kernel host."
else
	$(CLANG) $(CFLAGS) -c $< -o $@
endif

$(P2_OBJ): phase2/phase2_ringbuf_events.c
ifeq ($(HOST_OS),windows)
	@echo "Skip $(P2_OBJ): clang -target bpf requires Linux. Build this file on a 5.8+ kernel host."
else
	$(CLANG) $(CFLAGS) -c $< -o $@
endif

## ---- Phase 1: XDP packet filter ----
phase1: $(P1_OBJ) $(P1_LOADER)

$(P1_LOADER): phase1/phase1_loader.go
	cd phase1 && go build -o phase1-loader phase1_loader.go

## ---- Phase 2: ring buffer event monitor ----
phase2: $(P2_OBJ) $(P2_COLLECT)

$(P2_COLLECT): phase2/phase2_collector.go
	cd phase2 && go build -o phase2-collector phase2_collector.go

## ---- Phase 3: rules manager ----
phase3: $(P3_RULES)

$(P3_RULES): phase3/phase3_rules_manager.go
	cd phase3 && go build -o phase3-rules-manager phase3_rules_manager.go

## ---- Phase 4: REST API ----
phase4: $(P4_API)

$(P4_API): phase4/phase4_api_server.go
	cd phase4 && go build -o phase4-api-server phase4_api_server.go

generate-rules:
	@cp -n phase3/example_rules.json phase3/rules.json 2>/dev/null || true
	@echo "Rules file ready at phase3/example_rules.json"

install-deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libelf-dev libpcap-dev libbpf-dev linux-libc-dev golang-go
	@echo "Dependencies installed. Go module deps resolve automatically via 'go build'."

verify:
	@command -v go >/dev/null 2>&1 || { echo "go not found"; exit 1; }
	@go version
ifeq ($(HOST_OS),windows)
	@echo "Host is Windows: userspace will cross-compile to linux/amd64. BPF objects need a Linux 5.8+ machine with clang."
else
	@command -v clang >/dev/null 2>&1 || { echo "clang not found — run 'make install-deps'"; exit 1; }
	@uname -r | awk -F. '{ if ($$1 < 5 || ($$1 == 5 && $$2 < 8)) print "kernel " $$0 " may be too old (need 5.8+)"; else print "kernel " $$0 " OK" }'
endif
	@echo "Build environment check finished."

test:
	cd phase1 && go vet phase1_loader.go && go build -o /dev/null phase1_loader.go
	cd phase2 && go vet phase2_collector.go && go build -o /dev/null phase2_collector.go
	cd phase3 && go vet ./... && go build -o /dev/null phase3_rules_manager.go
	cd phase4 && go vet ./... && go build -o /dev/null phase4_api_server.go
	@echo "All phases pass go vet / build check."

clean:
	rm -f $(P1_OBJ) $(P1_LOADER) $(P1_LOADER).exe
	rm -f $(P2_OBJ) $(P2_COLLECT) $(P2_COLLECT).exe
	rm -f $(P3_RULES) $(P3_RULES).exe
	rm -f $(P4_API) $(P4_API).exe
	@echo "Build artifacts removed."

help:
	@echo "Plan-aligned targets:"
	@echo "  make all          userspace (4 binaries) + BPF objects when on Linux"
	@echo "  make userspace    phase1-loader, phase2-collector, phase3-rules-manager, phase4-api-server"
	@echo "  make phase1|2|3|4 one phase (BPF + Go, or Go-only for 3/4)"
	@echo "  make bpf          clang XDP objects (Linux only)"
	@echo "  make test verify clean install-deps generate-rules"
	@echo "Run on Linux: scripts/run-topology.sh"

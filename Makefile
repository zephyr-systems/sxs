.PHONY: help build install install-man clean run dev deps bundle-libs release

.DEFAULT_GOAL := build

BINARY := sxs
SHELLX_PATH := ../shellx

VERSION := 0.1.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION_ARG ?= $(VERSION)

BUILD_METADATA_FLAGS := -define:VERSION="$(VERSION)" -define:BUILD_TIME="$(BUILD_TIME)"

help:
	@echo "SXS (ShellX Scanner) - Build System"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  deps   - Clone ShellX dependency (if not already present)"
	@echo "  build  - Build the sxs binary"
	@echo "  bundle-libs - Copy required tree-sitter dylibs next to sxs binary"
	@echo "  release - Build release tarball and SHA (requires VERSION=...)"
	@echo "  install - Install to ~/.local/bin"
	@echo "  install-man - Install man page to ~/.local/share/man/man1"
	@echo "  clean  - Remove build artifacts"
	@echo "  dev    - Build with debug flags"

deps:
	@if [ ! -d "$(SHELLX_PATH)" ]; then \
		echo "Cloning ShellX dependency..."; \
		git clone https://github.com/zephyr-systems/shellx.git $(SHELLX_PATH); \
	else \
		echo "ShellX already present at $(SHELLX_PATH)"; \
	fi

build: deps bundle-libs
	odin build . -o:size -out:$(BINARY) $(BUILD_METADATA_FLAGS)

bundle-libs: deps
	@cp $(SHELLX_PATH)/libtree-sitter-*.dylib .

install: build
	@mkdir -p ~/.local/bin
	@mkdir -p ~/.local/share/man/man1
	@cp $(BINARY) ~/.local/bin/
	@cp $(SHELLX_PATH)/libtree-sitter-*.dylib ~/.local/bin/
	@cp docs/sxs.1 ~/.local/share/man/man1/
	@echo "Installed to ~/.local/bin/sxs"
	@echo "Installed man page to ~/.local/share/man/man1/sxs.1"

install-man:
	@mkdir -p ~/.local/share/man/man1
	@cp docs/sxs.1 ~/.local/share/man/man1/
	@echo "Installed man page to ~/.local/share/man/man1/sxs.1"

release:
	@if [ -z "$(VERSION_ARG)" ]; then \
		echo "VERSION is required (example: make release VERSION=0.1.0)"; \
		exit 1; \
	fi
	@./scripts/package_release.sh $(VERSION_ARG)

clean:
	rm -f $(BINARY)

dev: deps
	odin build . -o:none -debug -out:$(BINARY) $(BUILD_METADATA_FLAGS)

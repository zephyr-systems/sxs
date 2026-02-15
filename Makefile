.PHONY: help build install clean run dev deps

.DEFAULT_GOAL := build

BINARY := sxs
SHELLX_PATH := ../shellx

VERSION := 0.1.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

BUILD_METADATA_FLAGS := -define:VERSION="$(VERSION)" -define:BUILD_TIME="$(BUILD_TIME)"

help:
	@echo "SXS (ShellX Scanner) - Build System"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  deps   - Clone ShellX dependency (if not already present)"
	@echo "  build  - Build the sxs binary"
	@echo "  install - Install to ~/.local/bin"
	@echo "  clean  - Remove build artifacts"
	@echo "  dev    - Build with debug flags"

deps:
	@if [ ! -d "$(SHELLX_PATH)" ]; then \
		echo "Cloning ShellX dependency..."; \
		git clone https://github.com/zephyr-systems/shellx.git $(SHELLX_PATH); \
	else \
		echo "ShellX already present at $(SHELLX_PATH)"; \
	fi

build: deps
	odin build . -o:size -out:$(BINARY) $(BUILD_METADATA_FLAGS)

install: build
	@mkdir -p ~/.local/bin
	@cp $(BINARY) ~/.local/bin/
	@cp $(SHELLX_PATH)/libtree-sitter-*.dylib ~/.local/bin/
	@echo "Installed to ~/.local/bin/sxs"

clean:
	rm -f $(BINARY)

dev: deps
	odin build . -o:none -debug -out:$(BINARY) $(BUILD_METADATA_FLAGS)

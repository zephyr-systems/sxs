.PHONY: help build install clean run dev

.DEFAULT_GOAL := help

BINARY := sxs

VERSION := 0.1.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

BUILD_METADATA_FLAGS := -define:VERSION="$(VERSION)" -define:BUILD_TIME="$(BUILD_TIME)"

help:
	@echo "SXS (ShellX Scanner) - Build System"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build   - Build the sxs binary"
	@echo "  install - Install to ~/.local/bin"
	@echo "  clean   - Remove build artifacts"
	@echo "  dev     - Build with debug flags"

build:
	odin build . -o:size -out:$(BINARY) $(BUILD_METADATA_FLAGS)

install: build
	@mkdir -p ~/.local/bin
	@cp $(BINARY) ~/.local/bin/
	@echo "Installed to ~/.local/bin/sxs"

clean:
	rm -f $(BINARY)

dev:
	odin build . -o:none -debug -out:$(BINARY) $(BUILD_METADATA_FLAGS)

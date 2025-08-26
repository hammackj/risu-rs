BINARIES := risu-rs
TARGET_DIR := target/release
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

.PHONY: build hash tag push publish release

## Build optimized binaries
build:
	cargo build --release

## Generate SHA256 and SHA512 hashes for binaries
hash: build
	@for bin in $(BINARIES); do sha256sum $(TARGET_DIR)/$$bin > $(TARGET_DIR)/$$bin.sha256; sha512sum $(TARGET_DIR)/$$bin > $(TARGET_DIR)/$$bin.sha512; done

## Create an annotated git tag
# Usage: make tag VERSION=x.y.z
tag:
	@test -n "$(VERSION)" || (echo "Set VERSION=x.y.z" && exit 1)
	git tag -a v$(VERSION) -m "Release v$(VERSION)"

## Push commits and tags to origin
# Usage: make push VERSION=x.y.z
push:
	@test -n "$(VERSION)" || (echo "Set VERSION=x.y.z" && exit 1)
	git push origin $(CURRENT_BRANCH)
	git push origin v$(VERSION)

## Publish the crate to crates.io
publish:
	cargo publish

## Run the full release pipeline
# Usage: make release VERSION=x.y.z [PUBLISH=1]
release: hash tag push
	@if [ -n "$(PUBLISH)" ]; then cargo publish; fi

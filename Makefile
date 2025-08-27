BINARIES := risu-rs
TARGET_DIR := target/release
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

.PHONY: build checksum tag push publish release clean test test-sqlite test-postgres test-mysql notify

## Build optimized binaries
build:
	cargo build --release

## Generate SHA256 and SHA512 checksums for binaries
checksum: build
        cargo run --quiet --bin checksum -- $(addprefix $(TARGET_DIR)/,$(BINARIES))

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
release: checksum tag push
        @if [ -n "$(PUBLISH)" ]; then cargo publish; fi

## Remove build artifacts
clean:
        cargo clean
        rm -f checksum/*.sha256 checksum/*.sha512

## Run tests for all supported database backends
test: test-sqlite test-postgres test-mysql

## Run tests against the SQLite backend
test-sqlite:
	DATABASE_URL=sqlite://:memory: cargo test

## Run tests against the PostgreSQL backend
# Usage: make test-postgres DATABASE_URL=postgres://...
test-postgres:
	@test -n "$(DATABASE_URL)" || (echo "Set DATABASE_URL=postgres://..." && exit 1)
	cargo test --features postgres

## Run tests against the MySQL backend
# Usage: make test-mysql DATABASE_URL=mysql://...
test-mysql:
	@test -n "$(DATABASE_URL)" || (echo "Set DATABASE_URL=mysql://..." && exit 1)
	cargo test --features mysql

## Send a release notification to a webhook (e.g. Slack)
# Usage: make notify VERSION=x.y.z WEBHOOK=https://example.com/hook
notify:
	@test -n "$(VERSION)" || (echo "Set VERSION=x.y.z" && exit 1)
	@test -n "$(WEBHOOK)" || (echo "Set WEBHOOK=<url>" && exit 1)
	curl -X POST -H 'Content-type: application/json' --data '{"text":"risu-rs v$(VERSION) released"}' $(WEBHOOK)

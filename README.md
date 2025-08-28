# risu-rs

[![CI](https://github.com/hammackj/risu-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hammackj/risu-rs/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-HTML-blue.svg)](https://hammackj.github.io/risu-rs/coverage/)

A Rust rewrite of the Risu reporting utilities.

## Documentation

- [News](docs/NEWS.markdown)
- [Installation Guides](docs/install_guides/README.markdown)
- [Known Issues](docs/known_issues.markdown)

## Command-line usage

```bash
risu-rs --create-config-file       # write default config.yml
risu-rs migrate --create-tables    # run database migrations
risu-rs parse scan.nessus -o report.csv -t simple --post-process
risu-rs parse scan.nessus -o report.pdf -t simple --template-arg title="Custom Title"
risu-rs parse scan.nessus -o report.csv -t simple --blacklist 19506,34221
risu-rs parse scan.nessus -o report.pdf -t simple --whitelist 1001,1002
risu-rs --list-templates           # list available templates
risu-rs --list-post-process        # list post-process plugins
risu-rs --search-output keyword    # find keyword in plugin output
risu-rs --bug-report               # print environment details for bug reports
```

When reporting issues, run `risu-rs --bug-report` and include the generated
output in your bug report to help with troubleshooting.

Use `--blacklist` or `--whitelist` to control which plugin IDs are included in
the parsed report. Both options accept comma-separated ID lists. When a
whitelist is provided, only matching plugin IDs are kept; blacklisted IDs are
always removed.

The `--search-output` option performs a case-insensitive search of the
`plugin_output` column and prints matching host IP and plugin name pairs.

## Configuration

Settings are read from a YAML file (default: `config.yml`):

```yaml
database_url: sqlite://:memory:
database_backend: sqlite
log_level: info
template_paths:
  - ./templates
# Prefix added to report output paths
report_prefix: reports/
# Per-template default arguments keyed by template name
template_settings:
  simple:
    title: "Example Report"
# Override plugin severities keyed by plugin ID
severity_overrides:
  41028: 0
```

`report_prefix` prepends a directory to generated report paths. The
`template_settings` map supplies default template arguments; values provided on
the command line with `--template-arg` override these defaults. The
`severity_overrides` map adjusts item severities after parsing, allowing
specific plugin IDs to be downgraded or upgraded.

## Database backends

`risu-rs` supports SQLite, PostgreSQL and MySQL. Select a backend using the
`--database-backend` CLI option or the `database_backend` field in `config.yml`.
The corresponding Diesel feature must be enabled at compile time. For testing,
provide a `DATABASE_URL` pointing at the desired database and run:

```bash
make test-sqlite                        # default SQLite in-memory database
make test-postgres DATABASE_URL=postgres://user:pass@localhost/dbname
make test-mysql    DATABASE_URL=mysql://user:pass@localhost/dbname
```

PostgreSQL and MySQL tests require running database servers and the appropriate
Diesel features (`postgres` or `mysql`).

## Template API

Templates produce rendered reports from parsed scan data. Implement the
[`Template`](src/template.rs) trait and either register your template at runtime
or expose a `create_template` constructor in a dynamic library. The
`TemplateManager` searches for dynamic libraries in the following locations,
in order:

1. The built-in `src/templates` directory shipped with the project.
2. The current working directory.
3. `$HOME/.risu/templates`.
4. Any additional paths listed in the configuration `template_paths`.

Paths are searched non-recursively and duplicates are ignored.

## Post-process plugins

Post-processing plugins allow adjusting a parsed report before rendering. They
implement the [`PostProcess`](src/postprocess/mod.rs) trait and register using
the `inventory` crate so they are executed in order after parsing.

### Rollup plugins via TOML

Rollup plugins are defined in a TOML file (no rebuild needed):

- Search order: `RISU_ROLLUPS_FILE` → `./rollups.toml` → `~/.risu/rollups.toml`.
- Example (see `docs/rollups.example.toml`):

```
[[rollup]]
plugin_id = -99994
plugin_name = "Missing the latest Adobe Air Patches"
item_name = "Update to the latest Adobe Air"
description = "Adobe Air Patch Rollup"
plugin_ids = [56959, 52755, 53474]
```

If a TOML file is present, rollups are loaded from it. Built-in rollups have
been removed to keep changes data-driven.

## Release workflow

Maintainers can use the provided Makefile to cut releases:

- `make build` – compile optimized binaries.
- `make checksum` – write SHA256/SHA512 checksum files to `checksum/`.
- `make tag VERSION=x.y.z` – create an annotated git tag.
- `make push VERSION=x.y.z` – push commits and tags to `origin`.
- `make publish` – publish the crate to crates.io.
- `make release VERSION=x.y.z [PUBLISH=1]` – run build, checksum generation, tagging and pushing; set `PUBLISH=1` to also publish the crate.
- `make clean` – remove build artifacts.
- `make test` – run tests against all supported database backends (`make test-sqlite`, `make test-postgres`, `make test-mysql` to run individually).
- `make notify VERSION=x.y.z WEBHOOK=https://example.com/hook` – send a release announcement to a webhook (e.g. Slack).

Commit the generated files in `checksum/` and reference them in release notes so users can verify downloads:

```bash
sha256sum -c checksum/risu-rs.sha256
sha512sum -c checksum/risu-rs.sha512
```

## Developer utilities

- `scripts/generate_rollups.py` – regenerate rollup plugin definitions from the legacy Ruby project.
- `scripts/console_here` – open an interactive database console using the `config.yml` in the current directory:
   ```bash
   ./scripts/console_here
   ```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on building with the Rust toolchain and submitting patches.

Please review our [Code of Conduct](CODE_OF_CONDUCT.markdown) before participating.

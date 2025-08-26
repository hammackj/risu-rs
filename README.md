# risu-rs

A Rust rewrite of the Risu reporting utilities.

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
```

Use `--blacklist` or `--whitelist` to control which plugin IDs are included in
the parsed report. Both options accept comma-separated ID lists. When a
whitelist is provided, only matching plugin IDs are kept; blacklisted IDs are
always removed.

## Configuration

Settings are read from a YAML file (default: `config.yml`):

```yaml
database_url: sqlite://:memory:
log_level: info
template_paths:
  - ./templates
```

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

## Release workflow

Maintainers can use the provided Makefile to cut releases:

- `make build` – compile optimized binaries.
- `make hash` – build and emit SHA256/SHA512 checksum files alongside binaries.
- `make tag VERSION=x.y.z` – create an annotated git tag.
- `make push VERSION=x.y.z` – push commits and tags to `origin`.
- `make publish` – publish the crate to crates.io.
- `make release VERSION=x.y.z [PUBLISH=1]` – run build, hashing, tagging and pushing; set `PUBLISH=1` to also publish the crate.
- `make clean` – remove build artifacts.
- `make test` – run tests against all supported database backends (`make test-sqlite`, `make test-postgres`, `make test-mysql` to run individually).
- `make notify VERSION=x.y.z WEBHOOK=https://example.com/hook` – send a release announcement to a webhook (e.g. Slack).

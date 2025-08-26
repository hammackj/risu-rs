# risu-rs

A Rust rewrite of the Risu reporting utilities.

## Command-line usage

```bash
risu-rs --create-config-file       # write default config.yml
risu-rs migrate --create-tables    # run database migrations
risu-rs parse scan.nessus -o report.csv -t simple --post-process
risu-rs parse scan.nessus -o report.pdf -t simple --template-arg title="Custom Title"
risu-rs --list-templates           # list available templates
risu-rs --list-post-process        # list post-process plugins
```

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

1. A `templates/` directory next to the executable.
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

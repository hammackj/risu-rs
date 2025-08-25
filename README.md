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
or expose a `create_template` constructor in a dynamic library placed in one of
the configured `template_paths`.

## Post-process plugins

Post-processing plugins allow adjusting a parsed report before rendering. They
implement the [`PostProcess`](src/postprocess/mod.rs) trait and register using
the `inventory` crate so they are executed in order after parsing.

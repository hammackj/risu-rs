//! Command-line interface for `risu-rs`.
//!
//! ```text
//! risu-rs create-config              # write default config.yml
//! risu-rs migrate --create-tables    # run database migrations
//! risu-rs parse scan.nessus -o out.csv -t simple --post-process
//! risu-rs --list-templates           # list available templates
//! risu-rs --list-post-process        # list post-process plugins
//! ```

mod banner;
mod config;
mod console;
mod error;
mod graphs;
mod migrate;
mod models;
mod parser;
mod plugin_index;
mod postprocess;
mod renderer;
mod schema;
mod template;
mod templates;

use clap::{Parser, Subcommand};
use tracing::error;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Suppress the startup banner
    #[arg(long = "no-banner")]
    _no_banner: bool,
    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Log output format (plain or json)
    #[arg(long, value_parser = ["plain", "json"], default_value = "plain")]
    log_format: String,
    /// List available post-processing plugins
    #[arg(long = "list-post-process")]
    list_post_process: bool,
    /// List available templates
    #[arg(long = "list-templates")]
    list_templates: bool,
    /// Open an interactive database console
    #[arg(long)]
    console: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a configuration file with default values
    CreateConfig,
    /// Run database migrations
    Migrate {
        /// Create tables in the database
        #[arg(long)]
        create_tables: bool,
        /// Drop tables in the database
        #[arg(long)]
        drop_tables: bool,
    },
    /// Parse an input file and post process it
    Parse {
        /// File to parse
        file: std::path::PathBuf,
        /// Template to use for rendering
        #[arg(short, long, default_value = "simple")]
        template: String,
        /// Output file for generated document
        #[arg(short, long, default_value = "output.pdf")]
        output: std::path::PathBuf,
        /// Run post-processing plugins on the parsed data
        #[arg(long)]
        post_process: bool,
        /// Renderer to use (pdf, csv, nil). Use `nil` to discard output.
        #[arg(long, value_parser = ["pdf", "csv", "nil"])]
        renderer: Option<String>,
    },
    /// Index NASL plugins and store metadata
    PluginIndex {
        /// Directory containing NASL plugins
        dir: std::path::PathBuf,
    },
    /// Create a new template skeleton source file
    CreateTemplate {
        /// Template name
        #[arg(long)]
        name: Option<String>,
        /// Template author
        #[arg(long)]
        author: Option<String>,
        /// Renderer type (pdf, csv, nil)
        #[arg(long, value_parser = ["pdf", "csv", "nil"])]
        renderer: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        error!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), error::Error> {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|a| a == "--no-banner") {
        println!("{}", banner::random());
    }
    let cli = Cli::parse_from(args);

    init_logging(&cli.log_level, &cli.log_format);

    if cli.console {
        console::run()?;
        return Ok(());
    }

    if cli.list_post_process {
        postprocess::display();
        return Ok(());
    }

    if cli.list_templates {
        let cfg = config::load_config(std::path::Path::new("config.yml")).unwrap_or_default();
        let paths = cfg
            .template_paths
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
        let mut manager = template::TemplateManager::new(paths);
        manager.register(Box::new(template::SimpleTemplate));
        manager.register(Box::new(templates::TemplateTemplate));
        manager.register(Box::new(templates::HostSummaryTemplate));
        manager.register(Box::new(templates::PCIComplianceTemplate));
        manager.register(Box::new(templates::StigFindingsSummaryTemplate));
        manager.register(Box::new(templates::SslMediumStrCipherSupportTemplate));
        manager.load_templates().map_err(error::Error::Template)?;
        manager.display();
        return Ok(());
    }

    match cli.command {
        Some(Commands::CreateConfig) => {
            let path = std::path::Path::new("config.yml");
            config::create_config(path)?;
        }
        Some(Commands::Migrate {
            create_tables,
            drop_tables,
        }) => {
            migrate::run(create_tables, drop_tables)?;
        }
        Some(Commands::Parse {
            file,
            template: tmpl_name,
            output,
            post_process,
            renderer: renderer_opt,
        }) => {
            let mut report = parser::parse_file(&file)?;
            if post_process {
                postprocess::process(&mut report);
            }

            let cfg = config::load_config(std::path::Path::new("config.yml")).unwrap_or_default();
            let paths = cfg
                .template_paths
                .iter()
                .map(std::path::PathBuf::from)
                .collect();
            let mut manager = template::TemplateManager::new(paths);
            manager.register(Box::new(template::SimpleTemplate));
            manager.register(Box::new(templates::TemplateTemplate));
            manager.register(Box::new(templates::HostSummaryTemplate));
            manager.register(Box::new(templates::PCIComplianceTemplate));
            manager.register(Box::new(templates::StigFindingsSummaryTemplate));
            manager.register(Box::new(templates::SslMediumStrCipherSupportTemplate));
            manager.load_templates().map_err(error::Error::Template)?;
            let tmpl = manager.get(&tmpl_name).ok_or_else(|| {
                error::Error::Config(format!(
                    "unknown template '{tmpl_name}'. available: {:?}",
                    manager.available()
                ))
            })?;
            let renderer_choice = renderer_opt.clone();
            let mut renderer: Box<dyn renderer::Renderer> = match renderer_choice.as_deref() {
                Some("csv") => Box::new(renderer::CsvRenderer::new()),
                Some("nil") => Box::new(renderer::NilRenderer::new()),
                Some("pdf") => Box::new(renderer::PdfRenderer::new("Report")),
                None => match output.extension().and_then(|s| s.to_str()) {
                    Some("csv") => Box::new(renderer::CsvRenderer::new()),
                    _ => Box::new(renderer::PdfRenderer::new("Report")),
                },
                _ => unreachable!(),
            };
            tmpl.generate(&report, renderer.as_mut())
                .map_err(error::Error::Template)?;
            if renderer_choice.as_deref() != Some("nil") {
                let mut f = std::fs::File::create(&output)?;
                renderer.save(&mut f).map_err(error::Error::Template)?;
            } else {
                renderer
                    .save(&mut std::io::sink())
                    .map_err(error::Error::Template)?;
            }
        }
        Some(Commands::PluginIndex { dir }) => {
            plugin_index::run(&dir)?;
        }
        Some(Commands::CreateTemplate {
            name,
            author,
            renderer,
        }) => {
            let name = match name {
                Some(n) => n,
                None => template::create::prompt("Template name")?,
            };
            let author = match author {
                Some(a) => a,
                None => template::create::prompt("Author")?,
            };
            let renderer = match renderer {
                Some(r) => r,
                None => template::create::prompt("Renderer type (pdf, csv, nil)")?,
            };
            template::create::scaffold(&name, &author, &renderer)?;
        }
        None => {}
    }
    Ok(())
}

fn init_logging(level: &str, format: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        "json" => builder.json().init(),
        _ => builder.init(),
    }
}

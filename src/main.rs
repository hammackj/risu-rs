//! Command-line interface for `risu-rs`.
//!
//! ```text
//! risu-rs --create-config-file       # write default config.yml
//! risu-rs --create-tables            # run database migrations
//! risu-rs --test-connection          # check database connection
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
mod renderers;
use renderers as renderer;
mod schema;
mod template;
mod templates;
mod version;

use clap::{Parser, Subcommand};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use std::collections::{HashMap, HashSet};
use tracing::error;

#[derive(Parser)]
#[command(author, version, about, disable_version_flag = true)]
struct Cli {
    /// Suppress the startup banner
    #[arg(long = "no-banner")]
    _no_banner: bool,
    /// Increase output verbosity for debugging
    #[arg(long)]
    debug: bool,
    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Log output format (plain or json)
    #[arg(long, value_parser = ["plain", "json"], default_value = "plain")]
    log_format: String,
    /// Print application, Rust, and crate versions
    #[arg(long)]
    version: bool,
    /// List available post-processing plugins
    #[arg(long = "list-post-process")]
    list_post_process: bool,
    /// List available templates
    #[arg(long = "list-templates")]
    list_templates: bool,
    /// Comma-separated plugin IDs to blacklist
    #[arg(long, value_name = "id,...", value_delimiter = ',')]
    blacklist: Vec<i32>,
    /// Comma-separated plugin IDs to whitelist
    #[arg(long, value_name = "id,...", value_delimiter = ',')]
    whitelist: Vec<i32>,
    /// Open an interactive database console
    #[arg(long)]
    console: bool,
    /// Create tables in the database
    #[arg(long)]
    create_tables: bool,
    /// Drop tables in the database
    #[arg(long)]
    drop_tables: bool,
    /// Test database connection
    #[arg(long)]
    test_connection: bool,
    /// Print the current database schema version
    #[arg(long = "db-version")]
    db_version: bool,
    /// Path to configuration file
    #[arg(long = "config-file", value_name = "path")]
    config_file: Option<std::path::PathBuf>,
    /// Write a default configuration file and exit
    #[arg(long = "create-config-file", value_name = "path")]
    create_config_file: Option<Option<std::path::PathBuf>>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
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
        /// Template-specific arguments as `key=value` pairs
        #[arg(long = "template-arg", value_name = "key=value", value_parser = parse_key_val::<String, String>)]
        template_args: Vec<(String, String)>,
    },
    /// Index NASL plugins and store metadata
    PluginIndex {
        /// Directory containing NASL plugins
        dir: std::path::PathBuf,
    },
    /// Create a new template skeleton source file
    CreateTemplate {
        /// Template name
        name: String,
        /// Template author
        #[arg(long)]
        author: Option<String>,
        /// Renderer type (pdf, csv, nil)
        #[arg(long, value_parser = ["pdf", "csv", "nil"])]
        renderer: Option<String>,
    },
}

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
    U: std::str::FromStr,
    U::Err: std::fmt::Display,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    let key = s[..pos].parse::<T>().map_err(|e| e.to_string())?;
    let value = s[pos + 1..].parse::<U>().map_err(|e| e.to_string())?;
    Ok((key, value))
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

    if cli.version {
        version::print();
        return Ok(());
    }

    let level = if cli.debug {
        "debug"
    } else {
        cli.log_level.as_str()
    };
    init_logging(level, &cli.log_format);

    let config_path = cli
        .config_file
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("config.yml"));

    if let Some(path_opt) = cli.create_config_file {
        let path = path_opt.unwrap_or_else(|| config_path.clone());
        config::create_config(&path)?;
        println!("Created configuration file at {}", path.display());
        return Ok(());
    }

    if let Some(ref path) = cli.config_file {
        if !path.exists() {
            return Err(error::Error::Config(format!(
                "configuration file '{}' not found",
                path.display()
            )));
        }
    }

    let cfg = config::load_config(&config_path).unwrap_or_default();

    if cli.db_version {
        let mut conn = SqliteConnection::establish(&cfg.database_url)?;
        match version::db_version(&mut conn)? {
            Some(v) => println!("{v}"),
            None => println!("unknown"),
        }
        return Ok(());
    }

    if cli.create_tables || cli.drop_tables {
        migrate::run(cli.create_tables, cli.drop_tables)?;
        println!("Migration complete");
        return Ok(());
    }

    if cli.test_connection {
        match SqliteConnection::establish(&cfg.database_url) {
            Ok(_) => println!("Database connection successful"),
            Err(e) => {
                println!("Database connection failed: {e}");
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if let Ok(mut conn) = SqliteConnection::establish(&cfg.database_url) {
        version::warn_on_mismatch(&mut conn);
    }

    if cli.console {
        console::run(&config_path)?;
        return Ok(());
    }

    if cli.list_post_process {
        postprocess::display();
        return Ok(());
    }

    if cli.list_templates {
        let paths = cfg
            .template_paths
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
        let mut manager = template::TemplateManager::new(paths);
        manager.register(Box::new(template::SimpleTemplate));
        manager.register(Box::new(templates::TemplateTemplate));
        manager.register(Box::new(templates::HostSummaryTemplate));
        manager.register(Box::new(templates::MSPatchSummaryTemplate));
        manager.register(Box::new(templates::PCIComplianceTemplate));
        manager.register(Box::new(templates::StigFindingsSummaryTemplate));
        manager.register(Box::new(templates::SslMediumStrCipherSupportTemplate));
        manager.register(Box::new(templates::AuthenticationSummaryTemplate));
        manager.register(Box::new(templates::CoverSheetTemplate));
        manager.register(Box::new(templates::ExecSummaryTemplate));
        manager.register(Box::new(templates::ExecutiveSummaryDetailedTemplate));
        manager.register(Box::new(templates::ExploitablitySummaryTemplate));
        manager.register(Box::new(templates::FailedAuditsTemplate));
        manager.register(Box::new(templates::GraphsTemplate));
        manager.register(Box::new(templates::PluginSummaryTemplate));
        manager.register(Box::new(templates::RollupSummaryTemplate));
        manager.register(Box::new(templates::TalkingPointsTemplate));
        manager.register(Box::new(templates::TechnicalFindingsTemplate));
        manager.register(Box::new(templates::MSUpdateSummaryTemplate));
        manager.register(Box::new(templates::NotableTemplate));
        manager.register(Box::new(templates::Top25Template));
        manager.load_templates().map_err(error::Error::Template)?;
        manager.display();
        return Ok(());
    }

    match cli.command {
        Some(Commands::Parse {
            file,
            template: tmpl_name,
            output,
            post_process,
            renderer: renderer_opt,
            template_args,
        }) => {
            let blacklist: HashSet<i32> = cli.blacklist.iter().cloned().collect();
            let whitelist: HashSet<i32> = cli.whitelist.iter().cloned().collect();
            let mut report = parser::parse_file(&file)?;
            parser::filter_report(&mut report, &whitelist, &blacklist);
            if post_process {
                postprocess::process(&mut report, &whitelist, &blacklist);
            }

            let paths = cfg
                .template_paths
                .iter()
                .map(std::path::PathBuf::from)
                .collect();
            let mut manager = template::TemplateManager::new(paths);
            manager.register(Box::new(template::SimpleTemplate));
            manager.register(Box::new(templates::TemplateTemplate));
            manager.register(Box::new(templates::HostSummaryTemplate));
            manager.register(Box::new(templates::MSPatchSummaryTemplate));
            manager.register(Box::new(templates::PCIComplianceTemplate));
            manager.register(Box::new(templates::StigFindingsSummaryTemplate));
            manager.register(Box::new(templates::SslMediumStrCipherSupportTemplate));
            manager.register(Box::new(templates::AuthenticationSummaryTemplate));
            manager.register(Box::new(templates::CoverSheetTemplate));
            manager.register(Box::new(templates::ExecSummaryTemplate));
            manager.register(Box::new(templates::ExecutiveSummaryDetailedTemplate));
            manager.register(Box::new(templates::ExploitablitySummaryTemplate));
            manager.register(Box::new(templates::FailedAuditsTemplate));
            manager.register(Box::new(templates::GraphsTemplate));
            manager.register(Box::new(templates::PluginSummaryTemplate));
            manager.register(Box::new(templates::RollupSummaryTemplate));
            manager.register(Box::new(templates::TalkingPointsTemplate));
            manager.register(Box::new(templates::TechnicalFindingsTemplate));
            manager.register(Box::new(templates::MSUpdateSummaryTemplate));
            manager.register(Box::new(templates::NotableTemplate));
            manager.register(Box::new(templates::Top25Template));
            manager.load_templates().map_err(error::Error::Template)?;
            let tmpl = manager.get(&tmpl_name).ok_or_else(|| {
                error::Error::Config(format!(
                    "unknown template '{tmpl_name}'. available: {:?}",
                    manager.available()
                ))
            })?;
            let renderer_choice = renderer_opt.clone();
            let template_args: HashMap<String, String> = template_args.into_iter().collect();
            let title_arg = template_args
                .get("title")
                .cloned()
                .unwrap_or_else(|| "Report".to_string());
            let mut renderer: Box<dyn renderer::Renderer> = match renderer_choice.as_deref() {
                Some("csv") => Box::new(renderer::CsvRenderer::new()),
                Some("nil") => Box::new(renderer::NilRenderer::new()),
                Some("pdf") => Box::new(renderer::PdfRenderer::new(&title_arg)),
                None => match output.extension().and_then(|s| s.to_str()) {
                    Some("csv") => Box::new(renderer::CsvRenderer::new()),
                    _ => Box::new(renderer::PdfRenderer::new(&title_arg)),
                },
                _ => unreachable!(),
            };
            tmpl.generate(&report, renderer.as_mut(), &template_args)
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
            let author = author
                .or_else(|| std::env::var("USER").ok())
                .unwrap_or_else(|| "unknown".to_string());
            let renderer = renderer.unwrap_or_else(|| "pdf".to_string());
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

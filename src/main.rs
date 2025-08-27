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
mod analysis;
mod schema;
mod template;
mod templates;
mod version;

use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use ipnet::IpNet;
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
    /// List available templates. Templates are searched in built-in
    /// `src/templates`, the current working directory, and `$HOME/.risu/templates`.
    #[arg(long = "list-templates")]
    list_templates: bool,
    /// Search for a keyword in plugin output and print host/plugin pairs
    #[arg(long = "search-output", value_name = "keyword")]
    search_output: Option<String>,
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
    /// Parse a Nessus SQLite export and run post-processing plugins
    #[arg(long = "nessus-sqlite", value_name = "path")]
    nessus_sqlite: Option<std::path::PathBuf>,
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
        /// Template to use for rendering. Templates are searched in
        /// `src/templates`, the current directory, and `$HOME/.risu/templates`.
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
        /// Report title metadata
        #[arg(long = "report-title")]
        report_title: Option<String>,
        /// Report author metadata
        #[arg(long = "report-author")]
        report_author: Option<String>,
        /// Report company metadata
        #[arg(long = "report-company")]
        report_company: Option<String>,
        /// Report classification metadata
        #[arg(long = "report-classification")]
        report_classification: Option<String>,
        /// Only include findings older than the specified number of days
        #[arg(long = "older-than", value_name = "days")]
        older_than: Option<i64>,
        /// Only include hosts whose IP matches the CIDR
        #[arg(long = "host-ip", value_name = "cidr")]
        host_ip: Option<IpNet>,
        /// Only include hosts with the specified MAC address
        #[arg(long = "host-mac", value_name = "addr")]
        host_mac: Option<String>,
        /// Only include the host with the given internal ID
        #[arg(long = "host-id", value_name = "id")]
        host_id: Option<i32>,
        /// Only include items matching this plugin ID
        #[arg(long = "plugin-id", value_name = "id")]
        plugin_id: Option<i32>,
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
        match e {
            error::Error::InvalidDocument(msg) => {
                eprintln!("Failed to parse document: {msg}");
            }
            other => {
                error!("{other}");
            }
        }
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
        manager.register(Box::new(templates::AssetsTemplate));
        manager.register(Box::new(templates::HostSummaryTemplate));
        manager.register(Box::new(templates::MSPatchSummaryTemplate));
        manager.register(Box::new(templates::PCIComplianceTemplate));
        manager.register(Box::new(templates::StigFindingsSummaryTemplate));
        manager.register(Box::new(templates::SslMediumStrCipherSupportTemplate));
        manager.register(Box::new(templates::SslSummaryTemplate));
        manager.register(Box::new(templates::AuthenticationSummaryTemplate));
        manager.register(Box::new(templates::RemoteLocalSummaryTemplate));
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
        manager.register(Box::new(templates::NotableDetailedTemplate));
        manager.register(Box::new(templates::FindingStatisticsTemplate));
        manager.register(Box::new(templates::HostFindingsCsvTemplate));
        manager.register(Box::new(templates::HostFindingsCsvOlderThanTemplate));
        manager.register(Box::new(templates::Top25Template));
        manager.register(Box::new(templates::FindingsHostTemplate));
        manager.register(Box::new(templates::FindingsSummaryTemplate));
        manager.register(Box::new(templates::FindingsSummaryWithPluginIdTemplate));
        manager.register(Box::new(templates::MaliciousProcessDetectionTemplate));
        manager.register(Box::new(templates::MissingRootCausesTemplate));
        manager.register(Box::new(
            templates::MicrosoftWindowsUnquotedServicePathEnumerationTemplate,
        ));
        manager.register(Box::new(templates::MSWSUSFindingsTemplate));
        manager.register(Box::new(templates::ServiceInventoryTemplate));
        manager.register(Box::new(templates::UnsupportedOsTemplate));
        manager.load_templates().map_err(error::Error::Template)?;
        manager.display();
        return Ok(());
    }

    if let Some(keyword) = cli.search_output.as_deref() {
        use crate::schema::nessus_hosts::dsl::{ip, nessus_hosts};

        let mut conn = SqliteConnection::establish(&cfg.database_url)?;
        let items = models::Item::search_plugin_output(&mut conn, keyword, None)?;
        for item in items {
            let host = item
                .host_id
                .and_then(|hid| {
                    nessus_hosts
                        .find(hid)
                        .select(ip)
                        .first::<Option<String>>(&mut conn)
                        .ok()
                        .flatten()
                })
                .unwrap_or_else(|| "<unknown>".into());
            let plugin = item.plugin_name.unwrap_or_else(|| {
                item.plugin_id
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "<unknown>".into())
            });
            println!("{host} - {plugin}");
        }
        return Ok(());
    }

    if let Some(path) = cli.nessus_sqlite {
        let mut report = parser::parse_nessus_sqlite(&path)?;
        postprocess::process(
            &mut report,
            &HashSet::new(),
            &HashSet::new(),
            &parser::Filters::default(),
        );
        println!(
            "Parsed {} hosts, {} items, {} plugins, {} attachments",
            report.hosts.len(),
            report.items.len(),
            report.plugins.len(),
            report.attachments.len()
        );
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
            report_title,
            report_author,
            report_company,
            report_classification,
            older_than,
            host_ip,
            host_mac,
            host_id,
            plugin_id,
        }) => {
            let blacklist: HashSet<i32> = cli.blacklist.iter().cloned().collect();
            let whitelist: HashSet<i32> = cli.whitelist.iter().cloned().collect();
            let mut report = parser::parse_file(&file)?;
            parser::apply_severity_overrides(&mut report, &cfg.severity_overrides);
            let filters = parser::Filters {
                host_ip,
                host_mac,
                host_id,
                plugin_id,
            };
            report.filters = filters.clone();
            parser::filter_report(&mut report, &whitelist, &blacklist, &filters);
            if post_process {
                postprocess::process(&mut report, &whitelist, &blacklist, &filters);
            }

            // Populate report metadata from CLI or configuration
            report.report.title = report_title.or(cfg.report_title.clone());
            report.report.author = report_author.or(cfg.report_author.clone());
            report.report.company = report_company.or(cfg.report_company.clone());
            report.report.classification =
                report_classification.or(cfg.report_classification.clone());

            let paths = cfg
                .template_paths
                .iter()
                .map(std::path::PathBuf::from)
                .collect();
            let mut manager = template::TemplateManager::new(paths);
            manager.register(Box::new(template::SimpleTemplate));
            manager.register(Box::new(templates::TemplateTemplate));
            manager.register(Box::new(templates::AssetsTemplate));
            manager.register(Box::new(templates::HostSummaryTemplate));
            manager.register(Box::new(templates::MSPatchSummaryTemplate));
            manager.register(Box::new(templates::PCIComplianceTemplate));
            manager.register(Box::new(templates::StigFindingsSummaryTemplate));
            manager.register(Box::new(templates::SslMediumStrCipherSupportTemplate));
            manager.register(Box::new(templates::SslSummaryTemplate));
            manager.register(Box::new(templates::AuthenticationSummaryTemplate));
            manager.register(Box::new(templates::RemoteLocalSummaryTemplate));
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
            manager.register(Box::new(templates::NotableDetailedTemplate));
            manager.register(Box::new(templates::FindingStatisticsTemplate));
            manager.register(Box::new(templates::HostFindingsCsvTemplate));
            manager.register(Box::new(templates::HostFindingsCsvOlderThanTemplate));
            manager.register(Box::new(templates::Top25Template));
            manager.register(Box::new(templates::FindingsHostTemplate));
            manager.register(Box::new(templates::FindingsSummaryTemplate));
            manager.register(Box::new(templates::FindingsSummaryWithPluginIdTemplate));
            manager.register(Box::new(templates::MaliciousProcessDetectionTemplate));
            manager.register(Box::new(templates::MissingRootCausesTemplate));
            manager.register(Box::new(
                templates::MicrosoftWindowsUnquotedServicePathEnumerationTemplate,
            ));
            manager.register(Box::new(templates::MSWSUSFindingsTemplate));
            manager.register(Box::new(templates::ServiceInventoryTemplate));
            manager.register(Box::new(templates::UnsupportedOsTemplate));
            manager.load_templates().map_err(error::Error::Template)?;
            let mut template_args_map: HashMap<String, String> = cfg
                .template_settings
                .get(&tmpl_name)
                .cloned()
                .unwrap_or_default();
            template_args_map.extend(template_args.into_iter());
            if let Some(days) = older_than {
                let cutoff = (Utc::now() - Duration::days(days)).naive_utc();
                template_args_map.insert(
                    "cutoff_date".to_string(),
                    cutoff.format("%Y-%m-%d %H:%M:%S").to_string(),
                );
            }
            let output = cfg
                .report_prefix
                .as_ref()
                .map(|p| std::path::PathBuf::from(p).join(&output))
                .unwrap_or(output);
            let mut conn = SqliteConnection::establish(&cfg.database_url)?;
            let mut templater =
                template::templater::Templater::new(tmpl_name, &mut conn, output, manager);
            templater
                .generate(&report, renderer_opt.as_deref(), &template_args_map)
                .map_err(error::Error::Template)?;
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

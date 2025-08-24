mod config;
mod migrate;
mod parser;
mod postprocess;
mod schema;
mod models;
mod template;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateConfig => {
            let path = std::path::Path::new("config.yml");
            if let Err(e) = config::create_config(path) {
                eprintln!("failed to write config: {e}");
            }
        }
        Commands::Migrate {
            create_tables,
            drop_tables,
        } => {
            migrate::run(create_tables, drop_tables);
        }
        Commands::Parse { file, template: tmpl_name, output } => {
            match parser::parse_file(&file) {
                Ok(mut report) => {
                    postprocess::process(&mut report);

                    let cfg = config::load_config(std::path::Path::new("config.yml"))
                        .unwrap_or_default();
                    let paths = cfg.template_paths.iter().map(std::path::PathBuf::from).collect();
                    let mut manager = template::TemplateManager::new(paths);
                    manager.register(Box::new(template::SimpleTemplate));
                    if let Err(e) = manager.load_templates() {
                        eprintln!("failed to load templates: {e}");
                    }
                    match manager.get(&tmpl_name) {
                        Some(tmpl) => {
                            match std::fs::File::create(&output) {
                                Ok(mut f) => {
                                    if let Err(e) = tmpl.generate(&report, &mut f) {
                                        eprintln!("failed to generate output: {e}");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("failed to open output file: {e}");
                                }
                            }
                        }
                        None => {
                            eprintln!(
                                "unknown template '{}'\. available: {:?}",
                                tmpl_name,
                                manager.available()
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("failed to parse file: {e}");
                }
            }
        }
    }
}


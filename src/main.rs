mod config;
mod migrate;
mod models;
mod parser;
mod postprocess;
mod renderer;
mod schema;
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
        /// Run post-processing plugins on the parsed data
        #[arg(long)]
        post_process: bool,
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
        Commands::Parse {
            file,
            template: tmpl_name,
            output,
            post_process,
        } => match parser::parse_file(&file) {
            Ok(mut report) => {
                if post_process {
                    postprocess::process(&mut report);
                }

                let cfg =
                    config::load_config(std::path::Path::new("config.yml")).unwrap_or_default();
                let paths = cfg
                    .template_paths
                    .iter()
                    .map(std::path::PathBuf::from)
                    .collect();
                let mut manager = template::TemplateManager::new(paths);
                manager.register(Box::new(template::SimpleTemplate));
                if let Err(e) = manager.load_templates() {
                    eprintln!("failed to load templates: {e}");
                }
                match manager.get(&tmpl_name) {
                    Some(tmpl) => match std::fs::File::create(&output) {
                        Ok(mut f) => {
                            let mut renderer: Box<dyn renderer::Renderer> =
                                match output.extension().and_then(|s| s.to_str()) {
                                    Some("csv") => Box::new(renderer::CsvRenderer::new()),
                                    _ => Box::new(renderer::PdfRenderer::new("Report")),
                                };
                            if let Err(e) = tmpl.generate(&report, renderer.as_mut()) {
                                eprintln!("failed to generate output: {e}");
                            } else if let Err(e) = renderer.save(&mut f) {
                                eprintln!("failed to save output: {e}");
                            }
                        }
                        Err(e) => {
                            eprintln!("failed to open output file: {e}");
                        }
                    },
                    None => {
                        eprintln!(
                            "unknown template '{}'. available: {:?}",
                            tmpl_name,
                            manager.available()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("failed to parse file: {e}");
            }
        },
    }
}

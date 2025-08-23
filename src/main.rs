mod config;
mod migrate;
mod parser;
mod postprocess;
mod schema;
mod models;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a configuration file
    CreateConfig {
        /// Optional template to base the config on
        #[arg(long)]
        template: Option<String>,
    },
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
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateConfig { template } => {
            config::generate(template.as_deref());
        }
        Commands::Migrate {
            create_tables,
            drop_tables,
        } => {
            migrate::run(create_tables, drop_tables);
        }
        Commands::Parse { file } => {
            let data = parser::parse_file(&file);
            postprocess::process(&data);
        }
    }
}


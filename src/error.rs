use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Xml(#[from] quick_xml::Error),
    #[error(transparent)]
    Csv(#[from] csv::Error),
    #[error(transparent)]
    Database(#[from] diesel::result::Error),
    #[error(transparent)]
    Connection(#[from] diesel::ConnectionError),
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error("migration error: {0}")]
    Migration(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("template error: {0}")]
    Template(#[source] Box<dyn std::error::Error>),
    #[error("configuration error: {0}")]
    Config(String),
}

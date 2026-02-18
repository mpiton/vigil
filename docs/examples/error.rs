use thiserror::Error;

#[derive(Error, Debug)]
pub enum VigilError {
    #[error("Failed to collect system info: {0}")]
    Collection(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("AI analysis failed: {0}")]
    AiAnalysis(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Notification error: {0}")]
    Notification(String),

    #[error("Process action failed: {0}")]
    ProcessAction(String),
}

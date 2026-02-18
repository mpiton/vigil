use thiserror::Error;

use crate::domain::entities::snapshot::SystemSnapshot;

#[derive(Error, Debug)]
pub enum CollectionError {
    #[error("failed to collect system metrics: {0}")]
    MetricsUnavailable(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("timeout while collecting data")]
    Timeout,
}

pub trait SystemCollector: Send + Sync {
    /// Collect a full system snapshot.
    ///
    /// # Errors
    ///
    /// Returns `CollectionError` if metrics are unavailable,
    /// permission is denied, or collection times out.
    fn collect(&self) -> Result<SystemSnapshot, CollectionError>;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn collection_error_display() {
        let err = CollectionError::MetricsUnavailable("cpu stats".to_string());
        assert_eq!(
            err.to_string(),
            "failed to collect system metrics: cpu stats"
        );

        let err = CollectionError::Timeout;
        assert_eq!(err.to_string(), "timeout while collecting data");
    }
}

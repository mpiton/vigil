use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::domain::entities::alert::Alert;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::value_objects::action_risk::ActionRisk;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("storage read failed: {0}")]
    ReadFailed(String),
    #[error("storage write failed: {0}")]
    WriteFailed(String),
    #[error("entry not found: {0}")]
    NotFound(String),
}

/// Record of an executed action for audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRecord {
    pub timestamp: DateTime<Utc>,
    pub alert_id: Option<i64>,
    pub command: String,
    pub result: Option<String>,
    pub risk: ActionRisk,
}

pub trait AlertStore: Send + Sync {
    /// Persist an alert.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the write operation fails.
    fn save_alert(&self, alert: &Alert) -> Result<(), StoreError>;

    /// Retrieve all stored alerts.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the read operation fails.
    fn get_alerts(&self) -> Result<Vec<Alert>, StoreError>;

    /// Retrieve the most recent alerts, up to `count`.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the read operation fails.
    fn get_recent_alerts(&self, count: usize) -> Result<Vec<Alert>, StoreError>;
}

pub trait SnapshotStore: Send + Sync {
    /// Persist a system snapshot.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the write operation fails.
    fn save_snapshot(&self, snapshot: &SystemSnapshot) -> Result<(), StoreError>;

    /// Retrieve the most recent snapshot, if any.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the read operation fails.
    fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError>;
}

pub trait ActionLogStore: Send + Sync {
    /// Log an executed action for auditing.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the write operation fails.
    fn log_action(&self, record: &ActionRecord) -> Result<(), StoreError>;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn store_error_display() {
        let err = StoreError::ReadFailed("disk I/O".to_string());
        assert_eq!(err.to_string(), "storage read failed: disk I/O");

        let err = StoreError::NotFound("alert-123".to_string());
        assert_eq!(err.to_string(), "entry not found: alert-123");
    }
}

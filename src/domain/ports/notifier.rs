use thiserror::Error;

use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::diagnostic::AiDiagnostic;

#[derive(Error, Debug)]
pub enum NotificationError {
    #[error("failed to send notification: {0}")]
    SendFailed(String),
    #[error("notification channel unavailable: {0}")]
    ChannelUnavailable(String),
}

pub trait Notifier: Send + Sync {
    /// Send a notification for the given alert.
    ///
    /// # Errors
    ///
    /// Returns `NotificationError` if the notification fails to send
    /// or the channel is unavailable.
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError>;

    /// Send a notification for an AI diagnostic report.
    ///
    /// # Errors
    ///
    /// Returns `NotificationError` if the notification fails to send
    /// or the channel is unavailable.
    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError>;

    /// Notify that an action was automatically executed.
    ///
    /// # Errors
    ///
    /// Returns `NotificationError` if the notification fails.
    fn notify_action_executed(
        &self,
        action: &SuggestedAction,
        success: bool,
        output: &str,
    ) -> Result<(), NotificationError>;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn notification_error_display() {
        let err = NotificationError::SendFailed("smtp timeout".to_string());
        assert_eq!(err.to_string(), "failed to send notification: smtp timeout");

        let err = NotificationError::ChannelUnavailable("desktop".to_string());
        assert_eq!(err.to_string(), "notification channel unavailable: desktop");
    }
}

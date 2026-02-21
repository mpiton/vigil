use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::diagnostic::AiDiagnostic;
use crate::domain::ports::notifier::{NotificationError, Notifier};

/// Forwards notifications to multiple notifiers.
///
/// Calls each notifier in order, collecting errors.
/// Returns the first error encountered (if any), but always calls all notifiers.
pub struct CompositeNotifier {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl CompositeNotifier {
    #[must_use]
    pub fn new(notifiers: Vec<Box<dyn Notifier>>) -> Self {
        Self { notifiers }
    }
}

impl Default for CompositeNotifier {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl Notifier for CompositeNotifier {
    fn notify(&self, alert: &Alert) -> Result<(), NotificationError> {
        let mut first_error = None;
        for notifier in &self.notifiers {
            if let Err(e) = notifier.notify(alert) {
                tracing::warn!("Notification failed: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn notify_ai_diagnostic(&self, diagnostic: &AiDiagnostic) -> Result<(), NotificationError> {
        let mut first_error = None;
        for notifier in &self.notifiers {
            if let Err(e) = notifier.notify_ai_diagnostic(diagnostic) {
                tracing::warn!("Diagnostic notification failed: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn notify_action_executed(
        &self,
        action: &SuggestedAction,
        success: bool,
        output: &str,
    ) -> Result<(), NotificationError> {
        let mut first_error = None;
        for notifier in &self.notifiers {
            if let Err(e) = notifier.notify_action_executed(action, success, output) {
                tracing::warn!("Action notification failed: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::value_objects::action_risk::ActionRisk;
    use crate::domain::value_objects::severity::Severity;
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingNotifier {
        count: Arc<AtomicUsize>,
    }

    impl CountingNotifier {
        fn new(count: Arc<AtomicUsize>) -> Self {
            Self { count }
        }
    }

    impl Notifier for CountingNotifier {
        fn notify(&self, _alert: &Alert) -> Result<(), NotificationError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
        ) -> Result<(), NotificationError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FailingNotifier;

    impl Notifier for FailingNotifier {
        fn notify(&self, _alert: &Alert) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("test error".to_string()))
        }

        fn notify_ai_diagnostic(
            &self,
            _diagnostic: &AiDiagnostic,
        ) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("test error".to_string()))
        }

        fn notify_action_executed(
            &self,
            _action: &SuggestedAction,
            _success: bool,
            _output: &str,
        ) -> Result<(), NotificationError> {
            Err(NotificationError::SendFailed("test error".to_string()))
        }
    }

    fn make_alert() -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity: Severity::High,
            rule: "test".to_string(),
            title: "Test".to_string(),
            details: "Details".to_string(),
            suggested_actions: vec![],
        }
    }

    fn make_diagnostic() -> AiDiagnostic {
        AiDiagnostic {
            timestamp: Utc::now(),
            summary: "Test".to_string(),
            details: "Details".to_string(),
            severity: Severity::High,
            confidence: 0.9,
            suggested_actions: vec![],
        }
    }

    fn make_action() -> SuggestedAction {
        SuggestedAction {
            description: "Test action".to_string(),
            command: "echo test".to_string(),
            risk: ActionRisk::Safe,
        }
    }

    #[test]
    fn empty_composite_succeeds() {
        let composite = CompositeNotifier::default();
        assert!(composite.notify(&make_alert()).is_ok());
    }

    #[test]
    fn single_notifier_called() {
        let count = Arc::new(AtomicUsize::new(0));
        let composite =
            CompositeNotifier::new(vec![Box::new(CountingNotifier::new(Arc::clone(&count)))]);
        assert!(composite.notify(&make_alert()).is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multiple_notifiers_all_called() {
        let count = Arc::new(AtomicUsize::new(0));
        let composite = CompositeNotifier::new(vec![
            Box::new(CountingNotifier::new(Arc::clone(&count))),
            Box::new(CountingNotifier::new(Arc::clone(&count))),
            Box::new(CountingNotifier::new(Arc::clone(&count))),
        ]);
        assert!(composite.notify(&make_alert()).is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn error_from_one_still_calls_others() {
        let count = Arc::new(AtomicUsize::new(0));
        let composite = CompositeNotifier::new(vec![
            Box::new(CountingNotifier::new(Arc::clone(&count))),
            Box::new(FailingNotifier),
            Box::new(CountingNotifier::new(Arc::clone(&count))),
        ]);
        let result = composite.notify(&make_alert());
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn diagnostic_forwarded_to_all() {
        let count = Arc::new(AtomicUsize::new(0));
        let composite = CompositeNotifier::new(vec![
            Box::new(CountingNotifier::new(Arc::clone(&count))),
            Box::new(CountingNotifier::new(Arc::clone(&count))),
        ]);
        assert!(composite.notify_ai_diagnostic(&make_diagnostic()).is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn action_forwarded_to_all() {
        let count = Arc::new(AtomicUsize::new(0));
        let composite = CompositeNotifier::new(vec![
            Box::new(CountingNotifier::new(Arc::clone(&count))),
            Box::new(CountingNotifier::new(Arc::clone(&count))),
        ]);
        assert!(composite
            .notify_action_executed(&make_action(), true, "ok")
            .is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn all_failing_returns_first_error() {
        let composite =
            CompositeNotifier::new(vec![Box::new(FailingNotifier), Box::new(FailingNotifier)]);
        assert!(composite.notify(&make_alert()).is_err());
    }

    #[test]
    fn diagnostic_error_propagated() {
        let composite = CompositeNotifier::new(vec![Box::new(FailingNotifier)]);
        assert!(composite.notify_ai_diagnostic(&make_diagnostic()).is_err());
    }

    #[test]
    fn action_error_propagated() {
        let composite = CompositeNotifier::new(vec![Box::new(FailingNotifier)]);
        assert!(composite
            .notify_action_executed(&make_action(), true, "")
            .is_err());
    }
}

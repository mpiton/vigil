use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::entities::alert::SuggestedAction;
use crate::domain::value_objects::severity::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiDiagnostic {
    pub timestamp: DateTime<Utc>,
    pub summary: String,
    pub details: String,
    pub severity: Severity,
    pub confidence: f64,
    #[serde(default)]
    pub suggested_actions: Vec<SuggestedAction>,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn serde_roundtrip() {
        let diagnostic = AiDiagnostic {
            timestamp: Utc::now(),
            summary: "High memory usage detected".to_string(),
            details: "RAM usage at 92%, swap at 45%".to_string(),
            severity: Severity::High,
            confidence: 0.87,
            suggested_actions: vec![],
        };

        let json = serde_json::to_string(&diagnostic).expect("serialize");
        let deserialized: AiDiagnostic = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(diagnostic, deserialized);
    }
}

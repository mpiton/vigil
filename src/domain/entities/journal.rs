use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Entry from the system journal (journald)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub timestamp: DateTime<Utc>,
    pub priority: u8,
    pub unit: String,
    pub message: String,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn serde_roundtrip() {
        let entry = JournalEntry {
            timestamp: Utc::now(),
            priority: 3,
            unit: "sshd.service".to_string(),
            message: "Connection from 192.168.1.1".to_string(),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let deserialized: JournalEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.priority, 3);
        assert_eq!(deserialized.unit, "sshd.service");
    }
}

use std::sync::Mutex;

use chrono::{DateTime, Utc};

use crate::domain::entities::alert::Alert;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::ports::store::{
    ActionLogStore, ActionRecord, AlertStore, SnapshotStore, StoreError,
};

/// In-memory store for testing purposes.
pub struct InMemoryStore {
    alerts: Mutex<Vec<Alert>>,
    snapshots: Mutex<Vec<SystemSnapshot>>,
    action_logs: Mutex<Vec<ActionRecord>>,
}

impl InMemoryStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            alerts: Mutex::new(Vec::new()),
            snapshots: Mutex::new(Vec::new()),
            action_logs: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertStore for InMemoryStore {
    fn save_alert(&self, alert: &Alert) -> Result<(), StoreError> {
        self.alerts
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?
            .push(alert.clone());
        Ok(())
    }

    fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
        let mut alerts = self
            .alerts
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?
            .clone();
        alerts.reverse();
        Ok(alerts)
    }

    fn get_recent_alerts(&self, count: usize) -> Result<Vec<Alert>, StoreError> {
        let mut alerts = self
            .alerts
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?
            .clone();
        alerts.reverse();
        alerts.truncate(count);
        Ok(alerts)
    }

    fn get_alerts_since(&self, since: DateTime<Utc>) -> Result<Vec<Alert>, StoreError> {
        let mut alerts: Vec<Alert> = self
            .alerts
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?
            .iter()
            .filter(|a| a.timestamp >= since)
            .cloned()
            .collect();
        alerts.reverse();
        Ok(alerts)
    }
}

impl ActionLogStore for InMemoryStore {
    fn log_action(&self, record: &ActionRecord) -> Result<(), StoreError> {
        self.action_logs
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?
            .push(record.clone());
        Ok(())
    }
}

impl SnapshotStore for InMemoryStore {
    fn save_snapshot(&self, snapshot: &SystemSnapshot) -> Result<(), StoreError> {
        self.snapshots
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?
            .push(snapshot.clone());
        Ok(())
    }

    fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
        Ok(self
            .snapshots
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?
            .last()
            .cloned())
    }

    fn get_snapshots_since(&self, since: DateTime<Utc>) -> Result<Vec<SystemSnapshot>, StoreError> {
        let snapshots: Vec<SystemSnapshot> = self
            .snapshots
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?
            .iter()
            .filter(|s| s.timestamp >= since)
            .cloned()
            .collect();
        Ok(snapshots)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use crate::domain::ports::store::{ActionLogStore, ActionRecord};
    use crate::domain::value_objects::action_risk::ActionRisk;
    use crate::domain::value_objects::severity::Severity;

    fn make_alert(severity: Severity) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".into(),
            title: "Test alert".into(),
            details: "Test details".into(),
            suggested_actions: vec![],
        }
    }

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 8192,
                used_mb: 4096,
                available_mb: 4096,
                swap_total_mb: 2048,
                swap_used_mb: 0,
                usage_percent: 50.0,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 25.0,
                per_core_usage: vec![25.0],
                core_count: 4,
                load_avg_1m: 1.0,
                load_avg_5m: 0.8,
                load_avg_15m: 0.5,
            },
            processes: vec![],
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[test]
    fn new_creates_empty_store() {
        let store = InMemoryStore::new();
        let alerts = store.get_alerts().expect("get_alerts");
        assert!(alerts.is_empty());
        let snapshot = store.get_latest_snapshot().expect("get_latest_snapshot");
        assert!(snapshot.is_none());
    }

    #[test]
    fn save_and_get_alerts_round_trip() {
        let store = InMemoryStore::new();
        let alert = make_alert(Severity::High);
        let result = store.save_alert(&alert);
        assert!(result.is_ok());
        let alerts = store.get_alerts().expect("get_alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "test_rule");
    }

    #[test]
    fn get_recent_alerts_respects_limit() {
        let store = InMemoryStore::new();
        for _ in 0..5 {
            store.save_alert(&make_alert(Severity::Low)).expect("save");
        }
        let recent = store.get_recent_alerts(3).expect("get_recent_alerts");
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn alerts_returned_newest_first() {
        let store = InMemoryStore::new();
        store
            .save_alert(&make_alert(Severity::Low))
            .expect("save low");
        store
            .save_alert(&make_alert(Severity::Critical))
            .expect("save critical");
        let alerts = store.get_alerts().expect("get_alerts");
        assert_eq!(alerts.len(), 2);
        assert!(matches!(alerts[0].severity, Severity::Critical));
        assert!(matches!(alerts[1].severity, Severity::Low));
    }

    #[test]
    fn save_and_get_snapshot_round_trip() {
        let store = InMemoryStore::new();
        let snapshot = make_snapshot();
        let result = store.save_snapshot(&snapshot);
        assert!(result.is_ok());
        let latest = store.get_latest_snapshot().expect("get_latest_snapshot");
        assert!(latest.is_some());
        assert_eq!(latest.expect("some").cpu.core_count, 4);
    }

    #[test]
    fn get_latest_snapshot_returns_none_on_empty() {
        let store = InMemoryStore::new();
        let result = store.get_latest_snapshot().expect("get_latest_snapshot");
        assert!(result.is_none());
    }

    #[test]
    fn log_action_stores_record() {
        let store = InMemoryStore::new();
        let record = ActionRecord {
            timestamp: Utc::now(),
            alert_id: None,
            command: "kill -9 5678".to_string(),
            result: None,
            risk: ActionRisk::Dangerous,
        };
        let result = store.log_action(&record);
        assert!(result.is_ok());
    }

    #[test]
    fn get_alerts_since_filters_by_timestamp() {
        let store = InMemoryStore::new();
        let old_alert = Alert {
            timestamp: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .expect("parse")
                .with_timezone(&Utc),
            severity: Severity::Low,
            rule: "old".into(),
            title: "Old".into(),
            details: "Old".into(),
            suggested_actions: vec![],
        };
        store.save_alert(&old_alert).expect("save");
        store.save_alert(&make_alert(Severity::High)).expect("save");

        let cutoff = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .expect("parse")
            .with_timezone(&Utc);
        let recent = store.get_alerts_since(cutoff).expect("get_alerts_since");
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn get_snapshots_since_filters_by_timestamp() {
        let store = InMemoryStore::new();
        store.save_snapshot(&make_snapshot()).expect("save");

        let cutoff = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .expect("parse")
            .with_timezone(&Utc);
        let recent = store
            .get_snapshots_since(cutoff)
            .expect("get_snapshots_since");
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn default_creates_same_as_new() {
        let store = InMemoryStore::default();
        let alerts = store.get_alerts().expect("get_alerts");
        assert!(alerts.is_empty());
    }
}

use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::domain::entities::alert::{Alert, SuggestedAction};
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::ports::store::{
    ActionLogStore, ActionRecord, AlertStore, SnapshotStore, StoreError,
};
use crate::domain::value_objects::severity::Severity;

use super::migrations;

/// SQLite-backed persistent store for alerts and snapshots.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Create a new `SQLite` store at the given path.
    ///
    /// Expands `~`, creates parent directories, opens connection,
    /// sets WAL mode and pragmas, and initializes schema.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::WriteFailed` if the database cannot be opened or initialized.
    pub fn new(path: &str) -> Result<Self, StoreError> {
        let expanded = shellexpand::tilde(path);
        let db_path = PathBuf::from(expanded.as_ref());

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        }

        let conn =
            Connection::open(&db_path).map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        migrations::initialize_schema(&conn).map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Remove records older than the given retention period.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::WriteFailed` if deletion fails.
    pub fn cleanup_old(&self, retention_hours: u64) -> Result<(), StoreError> {
        let hours =
            i64::try_from(retention_hours).map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        let delta = chrono::TimeDelta::try_hours(hours)
            .ok_or_else(|| StoreError::WriteFailed("invalid retention hours".into()))?;
        let cutoff = Utc::now() - delta;
        let cutoff_str = cutoff.to_rfc3339();

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?;

        conn.execute(
            "DELETE FROM snapshots WHERE captured_at < ?1",
            params![cutoff_str],
        )
        .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        conn.execute(
            "DELETE FROM alerts WHERE created_at < ?1",
            params![cutoff_str],
        )
        .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        conn.execute(
            "DELETE FROM actions_log WHERE logged_at < ?1",
            params![cutoff_str],
        )
        .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        drop(conn);
        Ok(())
    }
}

fn parse_alert_row(row: &rusqlite::Row<'_>) -> Result<Alert, rusqlite::Error> {
    let created_at: String = row.get(0)?;
    let severity_str: String = row.get(1)?;
    let rule: String = row.get(2)?;
    let title: String = row.get(3)?;
    let details: String = row.get(4)?;
    let actions_json: String = row.get(5)?;

    let timestamp = DateTime::parse_from_rfc3339(&created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;

    let severity: Severity = serde_json::from_str(&format!("\"{severity_str}\"")).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let suggested_actions: Vec<SuggestedAction> =
        serde_json::from_str(&actions_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(Alert {
        timestamp,
        severity,
        rule,
        title,
        details,
        suggested_actions,
    })
}

impl AlertStore for SqliteStore {
    fn save_alert(&self, alert: &Alert) -> Result<(), StoreError> {
        let severity_json = serde_json::to_string(&alert.severity)
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        let severity_str = severity_json.trim_matches('"');

        let actions_json = serde_json::to_string(&alert.suggested_actions)
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?;

        conn.execute(
            "INSERT INTO alerts (created_at, severity, rule, title, details, actions) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                alert.timestamp.to_rfc3339(),
                severity_str,
                alert.rule,
                alert.title,
                alert.details,
                actions_json,
            ],
        )
        .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        drop(conn);
        Ok(())
    }

    fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?;

        let mut stmt = conn
            .prepare(
                "SELECT created_at, severity, rule, title, details, actions \
                 FROM alerts ORDER BY id DESC",
            )
            .map_err(|e| StoreError::ReadFailed(e.to_string()))?;

        let alerts = stmt
            .query_map([], parse_alert_row)
            .map_err(|e| StoreError::ReadFailed(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::ReadFailed(e.to_string()))?;

        drop(stmt);
        drop(conn);
        Ok(alerts)
    }

    fn get_recent_alerts(&self, count: usize) -> Result<Vec<Alert>, StoreError> {
        let limit = i64::try_from(count).map_err(|e| StoreError::ReadFailed(e.to_string()))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?;

        let mut stmt = conn
            .prepare(
                "SELECT created_at, severity, rule, title, details, actions \
                 FROM alerts ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| StoreError::ReadFailed(e.to_string()))?;

        let alerts = stmt
            .query_map(params![limit], parse_alert_row)
            .map_err(|e| StoreError::ReadFailed(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::ReadFailed(e.to_string()))?;

        drop(stmt);
        drop(conn);
        Ok(alerts)
    }
}

impl SnapshotStore for SqliteStore {
    fn save_snapshot(&self, snapshot: &SystemSnapshot) -> Result<(), StoreError> {
        let data =
            serde_json::to_string(snapshot).map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?;

        conn.execute(
            "INSERT INTO snapshots (captured_at, data) VALUES (?1, ?2)",
            params![snapshot.timestamp.to_rfc3339(), data],
        )
        .map_err(|e| StoreError::WriteFailed(e.to_string()))?;

        drop(conn);
        Ok(())
    }

    fn get_latest_snapshot(&self) -> Result<Option<SystemSnapshot>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::ReadFailed("lock poisoned".into()))?;

        let result = conn.query_row(
            "SELECT data FROM snapshots ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        );

        drop(conn);

        match result {
            Ok(data) => {
                let snapshot = serde_json::from_str(&data)
                    .map_err(|e| StoreError::ReadFailed(e.to_string()))?;
                Ok(Some(snapshot))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::ReadFailed(e.to_string())),
        }
    }
}

impl ActionLogStore for SqliteStore {
    fn log_action(&self, record: &ActionRecord) -> Result<(), StoreError> {
        let risk_str = serde_json::to_string(&record.risk)
            .map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        let risk_str = risk_str.trim_matches('"');
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?;
        conn.execute(
            "INSERT INTO actions_log (logged_at, alert_id, command, result, risk) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                record.timestamp.to_rfc3339(),
                record.alert_id,
                record.command,
                record.result,
                risk_str,
            ],
        )
        .map_err(|e| StoreError::WriteFailed(e.to_string()))?;
        drop(conn);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use crate::domain::ports::store::{ActionLogStore, ActionRecord};
    use crate::domain::value_objects::action_risk::ActionRisk;

    fn make_alert(severity: Severity) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".into(),
            title: "Test alert".into(),
            details: "Test details".into(),
            suggested_actions: vec![SuggestedAction {
                description: "Test action".into(),
                command: "echo test".into(),
                risk: ActionRisk::Safe,
            }],
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

    fn make_store() -> (SqliteStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let store = SqliteStore::new(path.to_str().expect("path")).expect("store");
        (store, dir)
    }

    #[test]
    fn new_creates_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let result = SqliteStore::new(path.to_str().expect("path"));
        assert!(result.is_ok());
    }

    #[test]
    fn save_and_get_alerts_round_trip() {
        let (store, _dir) = make_store();
        let alert = make_alert(Severity::High);

        assert!(store.save_alert(&alert).is_ok());

        let alerts = store.get_alerts().expect("get_alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].rule, "test_rule");
        assert_eq!(alerts[0].title, "Test alert");
        assert_eq!(alerts[0].details, "Test details");
    }

    #[test]
    fn get_recent_alerts_respects_limit() {
        let (store, _dir) = make_store();

        assert!(store.save_alert(&make_alert(Severity::Low)).is_ok());
        assert!(store.save_alert(&make_alert(Severity::Medium)).is_ok());
        assert!(store.save_alert(&make_alert(Severity::High)).is_ok());

        let recent = store.get_recent_alerts(2).expect("get_recent_alerts");
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn save_and_get_snapshot_round_trip() {
        let (store, _dir) = make_store();
        let snapshot = make_snapshot();

        assert!(store.save_snapshot(&snapshot).is_ok());

        let latest = store.get_latest_snapshot().expect("get_latest_snapshot");
        assert!(latest.is_some());
        let retrieved = latest.expect("some snapshot");
        assert_eq!(retrieved.cpu.core_count, 4);
        assert_eq!(retrieved.memory.total_mb, 8192);
    }

    #[test]
    fn get_latest_snapshot_returns_none_on_empty() {
        let (store, _dir) = make_store();
        let result = store.get_latest_snapshot().expect("get_latest_snapshot");
        assert!(result.is_none());
    }

    #[test]
    fn cleanup_removes_old_records() {
        let (store, _dir) = make_store();
        let old_alert = Alert {
            timestamp: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .expect("parse")
                .with_timezone(&Utc),
            severity: Severity::Low,
            rule: "old_rule".into(),
            title: "Old alert".into(),
            details: "Old".into(),
            suggested_actions: vec![],
        };
        assert!(store.save_alert(&old_alert).is_ok());

        assert!(store.cleanup_old(1).is_ok());

        let alerts = store.get_alerts().expect("get_alerts");
        assert!(alerts.is_empty());
    }

    #[test]
    fn alerts_with_suggested_actions_round_trip() {
        let (store, _dir) = make_store();
        let alert = Alert {
            timestamp: Utc::now(),
            severity: Severity::Critical,
            rule: "oom_risk".into(),
            title: "OOM imminent".into(),
            details: "RAM at 98%".into(),
            suggested_actions: vec![
                SuggestedAction {
                    description: "Kill process".into(),
                    command: "kill -9 1234".into(),
                    risk: ActionRisk::Dangerous,
                },
                SuggestedAction {
                    description: "Clear cache".into(),
                    command: "sync && echo 3 > /proc/sys/vm/drop_caches".into(),
                    risk: ActionRisk::Moderate,
                },
            ],
        };

        assert!(store.save_alert(&alert).is_ok());
        let alerts = store.get_alerts().expect("get_alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].suggested_actions.len(), 2);
        assert_eq!(alerts[0].suggested_actions[0].risk, ActionRisk::Dangerous);
        assert_eq!(alerts[0].suggested_actions[1].risk, ActionRisk::Moderate);
    }

    #[test]
    fn log_action_inserts_record() {
        let (store, _dir) = make_store();
        let record = ActionRecord {
            timestamp: Utc::now(),
            alert_id: None,
            command: "kill -15 1234".to_string(),
            result: Some("process terminated".to_string()),
            risk: ActionRisk::Moderate,
        };
        let result = store.log_action(&record);
        assert!(result.is_ok());
    }

    #[test]
    fn alerts_ordered_newest_first() {
        let (store, _dir) = make_store();

        let old_alert = Alert {
            timestamp: DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .expect("parse")
                .with_timezone(&Utc),
            severity: Severity::Low,
            rule: "old".into(),
            title: "Old alert".into(),
            details: "Old".into(),
            suggested_actions: vec![],
        };
        let new_alert = Alert {
            timestamp: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .expect("parse")
                .with_timezone(&Utc),
            severity: Severity::High,
            rule: "new".into(),
            title: "New alert".into(),
            details: "New".into(),
            suggested_actions: vec![],
        };

        assert!(store.save_alert(&old_alert).is_ok());
        assert!(store.save_alert(&new_alert).is_ok());

        let alerts = store.get_alerts().expect("get_alerts");
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].rule, "new");
        assert_eq!(alerts[1].rule, "old");
    }
}

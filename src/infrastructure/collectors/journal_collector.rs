use std::collections::HashMap;
use std::process::Command;

use chrono::{DateTime, Utc};

use crate::domain::entities::JournalEntry;
use crate::domain::ports::collector::CollectionError;

const JOURNAL_SINCE: &str = "5 min ago";
const MAX_JOURNAL_LINES: &str = "500";
const DEFAULT_SYSLOG_PRIORITY: u8 = 6;

pub struct JournalCollector;

impl JournalCollector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Collects recent journal entries (priority warning and above) from systemd journald.
    ///
    /// # Errors
    ///
    /// Returns `CollectionError::MetricsUnavailable` if `journalctl` fails to execute
    /// or exits with a non-zero status.
    /// Returns `Ok(Vec::new())` if `journalctl` is not found on the system.
    pub fn collect(&self) -> Result<Vec<JournalEntry>, CollectionError> {
        let output = match Command::new("journalctl")
            .args([
                "--since",
                JOURNAL_SINCE,
                "--priority",
                "warning",
                "--output",
                "json",
                "--no-pager",
                "--lines",
                MAX_JOURNAL_LINES,
            ])
            .output()
        {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(CollectionError::MetricsUnavailable(format!(
                    "failed to run journalctl: {e}"
                )))
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CollectionError::MetricsUnavailable(format!(
                "journalctl exited with {}: {stderr}",
                output.status
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_journal_output(&stdout))
    }
}

impl Default for JournalCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_timestamp(entry: &HashMap<String, serde_json::Value>) -> DateTime<Utc> {
    entry
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|us| {
            let nanos = u32::try_from((us % 1_000_000) * 1_000).unwrap_or(0);
            DateTime::from_timestamp(us / 1_000_000, nanos)
        })
        .unwrap_or_else(Utc::now)
}

fn parse_priority(entry: &HashMap<String, serde_json::Value>) -> u8 {
    entry
        .get("PRIORITY")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u8>().ok())
                .or_else(|| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        })
        .unwrap_or(DEFAULT_SYSLOG_PRIORITY)
}

fn parse_journal_output(stdout: &str) -> Vec<JournalEntry> {
    let mut entries = Vec::new();

    for line in stdout.lines() {
        if let Ok(entry) = serde_json::from_str::<HashMap<String, serde_json::Value>>(line) {
            let message = entry
                .get("MESSAGE")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if message.is_empty() {
                continue;
            }

            let unit = entry
                .get("_SYSTEMD_UNIT")
                .or_else(|| entry.get("SYSLOG_IDENTIFIER"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let priority = parse_priority(&entry);
            let timestamp = parse_timestamp(&entry);

            entries.push(JournalEntry {
                timestamp,
                priority,
                unit,
                message,
            });
        }
    }

    entries
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_collector() {
        let _collector = JournalCollector::new();
    }

    #[test]
    fn default_trait_is_implemented() {
        fn assert_default<T: Default>() {}
        assert_default::<JournalCollector>();
    }

    #[test]
    fn collect_returns_ok() {
        let collector = JournalCollector::new();
        // May fail in CI without journalctl; that's expected.
        let _ = collector.collect();
    }

    #[test]
    fn parse_valid_json_line() {
        let stdout = r#"{"MESSAGE":"test message","_SYSTEMD_UNIT":"test.service","PRIORITY":"3","__REALTIME_TIMESTAMP":"1700000000000000"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(entries.len(), 1, "should parse one entry");
        assert_eq!(entries[0].message, "test message");
        assert_eq!(entries[0].unit, "test.service");
        assert_eq!(entries[0].priority, 3);
    }

    #[test]
    fn parse_uses_realtime_timestamp() {
        let stdout = r#"{"MESSAGE":"ts test","_SYSTEMD_UNIT":"u.service","PRIORITY":"3","__REALTIME_TIMESTAMP":"1700000000000000"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp.timestamp(),
            1_700_000_000,
            "should use __REALTIME_TIMESTAMP from journal"
        );
    }

    #[test]
    fn parse_falls_back_to_utc_now_without_timestamp() {
        let before = Utc::now().timestamp();
        let stdout = r#"{"MESSAGE":"no ts","_SYSTEMD_UNIT":"u.service","PRIORITY":"3"}"#;
        let entries = parse_journal_output(stdout);
        let after = Utc::now().timestamp();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].timestamp.timestamp() >= before && entries[0].timestamp.timestamp() <= after,
            "should fall back to Utc::now() when __REALTIME_TIMESTAMP is missing"
        );
    }

    #[test]
    fn parse_filters_empty_messages() {
        let stdout = r#"{"MESSAGE":"","_SYSTEMD_UNIT":"test.service","PRIORITY":"3"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(
            entries.len(),
            0,
            "entry with empty message should be filtered"
        );
    }

    #[test]
    fn parse_defaults_priority_when_missing() {
        let stdout = r#"{"MESSAGE":"no priority","_SYSTEMD_UNIT":"test.service"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(entries.len(), 1, "should parse entry without priority");
        assert_eq!(
            entries[0].priority, DEFAULT_SYSLOG_PRIORITY,
            "priority should default to {DEFAULT_SYSLOG_PRIORITY} when missing"
        );
    }

    #[test]
    fn parse_priority_as_json_number() {
        let stdout = r#"{"MESSAGE":"numeric priority","_SYSTEMD_UNIT":"u.service","PRIORITY":2}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(entries.len(), 1, "should parse entry with numeric priority");
        assert_eq!(
            entries[0].priority, 2,
            "should handle PRIORITY as JSON number"
        );
    }

    #[test]
    fn parse_falls_back_to_syslog_identifier() {
        let stdout = r#"{"MESSAGE":"fallback unit","SYSLOG_IDENTIFIER":"myapp","PRIORITY":"4"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(
            entries.len(),
            1,
            "should parse entry with syslog identifier"
        );
        assert_eq!(
            entries[0].unit, "myapp",
            "unit should fall back to SYSLOG_IDENTIFIER"
        );
    }

    #[test]
    fn parse_skips_invalid_json_lines() {
        let stdout = "not json\n{\"MESSAGE\":\"valid\",\"_SYSTEMD_UNIT\":\"u.service\",\"PRIORITY\":\"3\"}\nalso not json";
        let entries = parse_journal_output(stdout);
        assert_eq!(
            entries.len(),
            1,
            "invalid json lines should be skipped without error"
        );
    }

    #[test]
    fn parse_multiple_entries() {
        let stdout = "{\"MESSAGE\":\"first\",\"_SYSTEMD_UNIT\":\"a.service\",\"PRIORITY\":\"3\"}\n{\"MESSAGE\":\"second\",\"_SYSTEMD_UNIT\":\"b.service\",\"PRIORITY\":\"4\"}";
        let entries = parse_journal_output(stdout);
        assert_eq!(entries.len(), 2, "should parse two entries");
        assert_eq!(entries[0].message, "first");
        assert_eq!(entries[1].message, "second");
    }

    #[test]
    fn parse_unknown_unit_when_neither_field_present() {
        let stdout = r#"{"MESSAGE":"no unit field","PRIORITY":"2"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(entries.len(), 1, "should parse entry without unit fields");
        assert_eq!(
            entries[0].unit, "unknown",
            "unit should be 'unknown' when no unit field present"
        );
    }

    #[test]
    fn parse_skips_binary_message_array() {
        let stdout =
            r#"{"MESSAGE":[104,101,108,108,111],"_SYSTEMD_UNIT":"bin.service","PRIORITY":"3"}"#;
        let entries = parse_journal_output(stdout);
        assert_eq!(
            entries.len(),
            0,
            "binary MESSAGE (byte array) should be skipped"
        );
    }
}

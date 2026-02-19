use rusqlite::Connection;

/// Initialize the database schema, creating tables if they don't exist.
///
/// # Errors
/// Returns `rusqlite::Error` if any SQL statement fails.
pub fn initialize_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT    NOT NULL,
            data        TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            rule        TEXT    NOT NULL,
            title       TEXT    NOT NULL,
            details     TEXT    NOT NULL,
            actions     TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS actions_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            logged_at   TEXT    NOT NULL,
            alert_id    INTEGER,
            command     TEXT    NOT NULL,
            result      TEXT,
            risk        TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hour_of_day   INTEGER NOT NULL,
            metric        TEXT    NOT NULL,
            mean          REAL    NOT NULL,
            stddev        REAL    NOT NULL,
            sample_count  INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_snapshots_captured_at ON snapshots(captured_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
        CREATE INDEX IF NOT EXISTS idx_actions_log_logged_at ON actions_log(logged_at);
        CREATE INDEX IF NOT EXISTS idx_baselines_metric ON baselines(metric, hour_of_day);",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[allow(clippy::expect_used)]
    #[test]
    fn test_initialize_schema_creates_all_tables() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        let result = initialize_schema(&conn);
        assert!(result.is_ok());

        for table in &["snapshots", "alerts", "actions_log", "baselines"] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                    [table],
                    |row| row.get(0),
                )
                .expect("query sqlite_master");
            assert_eq!(count, 1, "table {table} should exist");
        }
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn test_initialize_schema_is_idempotent() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        let first = initialize_schema(&conn);
        assert!(first.is_ok());
        let second = initialize_schema(&conn);
        assert!(second.is_ok());
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn test_tables_have_expected_columns() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        assert!(initialize_schema(&conn).is_ok());

        let check_column = |table: &str, column: &str| {
            let count: i64 = conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name='{column}'"
                    ),
                    [],
                    |row| row.get(0),
                )
                .expect("pragma_table_info");
            assert_eq!(count, 1, "column {column} should exist in {table}");
        };

        check_column("snapshots", "id");
        check_column("snapshots", "captured_at");
        check_column("snapshots", "data");

        check_column("alerts", "id");
        check_column("alerts", "created_at");
        check_column("alerts", "severity");
        check_column("alerts", "rule");
        check_column("alerts", "title");
        check_column("alerts", "details");
        check_column("alerts", "actions");

        check_column("actions_log", "id");
        check_column("actions_log", "logged_at");
        check_column("actions_log", "alert_id");
        check_column("actions_log", "command");
        check_column("actions_log", "result");
        check_column("actions_log", "risk");

        check_column("baselines", "id");
        check_column("baselines", "hour_of_day");
        check_column("baselines", "metric");
        check_column("baselines", "mean");
        check_column("baselines", "stddev");
        check_column("baselines", "sample_count");
    }
}

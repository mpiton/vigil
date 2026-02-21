use chrono::Utc;
use colored::Colorize;

use crate::domain::ports::collector::SystemCollector;
use crate::domain::ports::process_manager::{ProcessError, ProcessManager, Signal};
use crate::domain::ports::store::{ActionLogStore, ActionRecord};
use crate::domain::value_objects::action_risk::ActionRisk;
use crate::presentation::cli::formatters::status_fmt::print_section_header;

/// Terminate a process by PID with POSIX signal delivery.
///
/// Display process information (if available), send
/// SIGTERM (default) or SIGKILL (`--force`), and log the action.
///
/// # Errors
///
/// Returns an error if the process is not found, permission is denied,
/// or the signal cannot be delivered.
pub fn run_kill(
    collector: &dyn SystemCollector,
    manager: &dyn ProcessManager,
    action_log: Option<&dyn ActionLogStore>,
    pid: u32,
    force: bool,
) -> anyhow::Result<()> {
    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };

    // Show process info before killing (best effort)
    if let Ok(snapshot) = collector.collect() {
        if let Some(proc_info) = snapshot.processes.iter().find(|p| p.pid == pid) {
            print_section_header("Process to terminate");
            println!("  {}: {}", "PID".bold(), proc_info.pid);
            println!("  {}: {}", "Name".bold(), proc_info.name);
            println!("  {}: {}", "Command".bold(), proc_info.cmdline);
            println!("  {}: {} MB", "RAM".bold(), proc_info.rss_mb);
            println!("  {}: {:.1}%", "CPU".bold(), proc_info.cpu_percent);
        }
    }

    let signal = if force {
        Signal::Kill
    } else {
        Signal::Terminate
    };

    match manager.signal(pid, signal) {
        Ok(()) => {
            println!(
                "{} Signal {} sent to process {}",
                "✓".green().bold(),
                signal_name.bold(),
                pid
            );

            // Log action to store if available
            if let Some(store) = action_log {
                let command = if force {
                    format!("kill -9 {pid}")
                } else {
                    format!("kill -15 {pid}")
                };
                let record = ActionRecord {
                    timestamp: Utc::now(),
                    alert_id: None,
                    command,
                    result: Some("process terminated".to_string()),
                    risk: if force {
                        ActionRisk::Dangerous
                    } else {
                        ActionRisk::Moderate
                    },
                };
                if let Err(e) = store.log_action(&record) {
                    tracing::warn!("Logging failed: {e}");
                }
            }

            Ok(())
        }
        Err(ProcessError::NotFound(p)) => {
            anyhow::bail!("Process with PID {p} not found")
        }
        Err(ProcessError::PermissionDenied(p)) => {
            anyhow::bail!("Permission denied for process {p}")
        }
        Err(ProcessError::SignalFailed(msg)) => {
            anyhow::bail!("Failed to send signal: {msg}")
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::process::{ProcessInfo, ProcessState};
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use crate::domain::ports::collector::CollectionError;
    use crate::domain::ports::store::StoreError;
    use colored::control;
    use std::sync::Mutex;

    fn disable_colors() {
        control::set_override(false);
    }

    // --- Mock Collector ---

    struct MockCollector {
        snapshot: SystemSnapshot,
    }

    impl SystemCollector for MockCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Ok(self.snapshot.clone())
        }
    }

    struct FailingCollector;

    impl SystemCollector for FailingCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Err(CollectionError::MetricsUnavailable("test error".into()))
        }
    }

    // --- Mock ProcessManager ---

    struct MockProcessManager {
        last_signal: Mutex<Option<Signal>>,
    }

    impl MockProcessManager {
        fn new() -> Self {
            Self {
                last_signal: Mutex::new(None),
            }
        }
    }

    impl ProcessManager for MockProcessManager {
        fn kill(&self, pid: u32) -> Result<(), ProcessError> {
            self.signal(pid, Signal::Kill)
        }

        fn signal(&self, _pid: u32, signal: Signal) -> Result<(), ProcessError> {
            *self.last_signal.lock().expect("lock") = Some(signal);
            Ok(())
        }
    }

    struct NotFoundManager;

    impl ProcessManager for NotFoundManager {
        fn kill(&self, pid: u32) -> Result<(), ProcessError> {
            self.signal(pid, Signal::Kill)
        }

        fn signal(&self, pid: u32, _signal: Signal) -> Result<(), ProcessError> {
            Err(ProcessError::NotFound(pid))
        }
    }

    struct PermissionDeniedManager;

    impl ProcessManager for PermissionDeniedManager {
        fn kill(&self, pid: u32) -> Result<(), ProcessError> {
            self.signal(pid, Signal::Kill)
        }

        fn signal(&self, pid: u32, _signal: Signal) -> Result<(), ProcessError> {
            Err(ProcessError::PermissionDenied(pid))
        }
    }

    struct SignalFailedManager;

    impl ProcessManager for SignalFailedManager {
        fn kill(&self, pid: u32) -> Result<(), ProcessError> {
            self.signal(pid, Signal::Kill)
        }

        fn signal(&self, _pid: u32, _signal: Signal) -> Result<(), ProcessError> {
            Err(ProcessError::SignalFailed("test failure".into()))
        }
    }

    // --- Mock ActionLogStore ---

    struct MockActionLog {
        records: Mutex<Vec<ActionRecord>>,
    }

    impl MockActionLog {
        fn new() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
            }
        }
    }

    impl ActionLogStore for MockActionLog {
        fn log_action(&self, record: &ActionRecord) -> Result<(), StoreError> {
            self.records
                .lock()
                .map_err(|_| StoreError::WriteFailed("lock poisoned".into()))?
                .push(record.clone());
            Ok(())
        }
    }

    struct FailingActionLog;

    impl ActionLogStore for FailingActionLog {
        fn log_action(&self, _record: &ActionRecord) -> Result<(), StoreError> {
            Err(StoreError::WriteFailed("disk full".into()))
        }
    }

    // --- Factory helpers ---

    fn make_snapshot_with_process(pid: u32) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 4000,
                available_mb: 12384,
                swap_total_mb: 8192,
                swap_used_mb: 0,
                usage_percent: 24.4,
                swap_percent: 0.0,
            },
            cpu: CpuInfo {
                global_usage_percent: 10.0,
                per_core_usage: vec![10.0],
                core_count: 4,
                load_avg_1m: 0.5,
                load_avg_5m: 0.4,
                load_avg_15m: 0.3,
            },
            processes: vec![ProcessInfo {
                pid,
                ppid: 1,
                name: "test-process".to_string(),
                cmdline: "/usr/bin/test --flag".to_string(),
                state: ProcessState::Running,
                cpu_percent: 25.0,
                rss_mb: 256,
                vms_mb: 1024,
                user: "root".to_string(),
                start_time: 1000,
                open_fds: 42,
            }],
            disks: vec![],
            journal_entries: vec![],
        }
    }

    #[test]
    fn kill_sigterm_success() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = MockProcessManager::new();
        let result = run_kill(&collector, &manager, None, 1234, false);
        assert!(result.is_ok());
        let sent = *manager.last_signal.lock().expect("lock");
        assert_eq!(sent, Some(Signal::Terminate));
    }

    #[test]
    fn kill_sigkill_success() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = MockProcessManager::new();
        let result = run_kill(&collector, &manager, None, 1234, true);
        assert!(result.is_ok());
        let sent = *manager.last_signal.lock().expect("lock");
        assert_eq!(sent, Some(Signal::Kill));
    }

    #[test]
    fn kill_process_not_found() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = NotFoundManager;
        let result = run_kill(&collector, &manager, None, 1234, false);
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("1234"));
    }

    #[test]
    fn kill_permission_denied() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = PermissionDeniedManager;
        let result = run_kill(&collector, &manager, None, 1234, false);
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(err.to_string().contains("Permission"));
    }

    #[test]
    fn kill_signal_failed() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = SignalFailedManager;
        let result = run_kill(&collector, &manager, None, 1234, false);
        assert!(result.is_err());
    }

    #[test]
    fn kill_logs_action_on_success() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = MockProcessManager::new();
        let log = MockActionLog::new();
        let result = run_kill(&collector, &manager, Some(&log), 1234, false);
        assert!(result.is_ok());
        let records = log.records.lock().expect("lock").clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].command, "kill -15 1234");
        assert_eq!(records[0].risk, ActionRisk::Moderate);
    }

    #[test]
    fn kill_force_logs_dangerous_action() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = MockProcessManager::new();
        let log = MockActionLog::new();
        let result = run_kill(&collector, &manager, Some(&log), 1234, true);
        assert!(result.is_ok());
        let records = log.records.lock().expect("lock").clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].command, "kill -9 1234");
        assert_eq!(records[0].risk, ActionRisk::Dangerous);
    }

    #[test]
    fn kill_log_failure_does_not_propagate() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(1234),
        };
        let manager = MockProcessManager::new();
        let log = FailingActionLog;
        let result = run_kill(&collector, &manager, Some(&log), 1234, false);
        assert!(result.is_ok());
    }

    #[test]
    fn kill_collection_failure_still_kills() {
        disable_colors();
        let collector = FailingCollector;
        let manager = MockProcessManager::new();
        let result = run_kill(&collector, &manager, None, 1234, false);
        assert!(result.is_ok());
    }

    #[test]
    fn kill_no_matching_process_still_kills() {
        disable_colors();
        let collector = MockCollector {
            snapshot: make_snapshot_with_process(9999),
        };
        let manager = MockProcessManager::new();
        let result = run_kill(&collector, &manager, None, 1234, false);
        assert!(result.is_ok());
    }
}

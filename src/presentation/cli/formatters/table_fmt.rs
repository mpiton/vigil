use crate::domain::entities::process::{ProcessInfo, ProcessState};
use colored::Colorize;

/// Formats the top N processes sorted by RAM usage as an aligned table.
///
/// # Returns
///
/// A multi-line string with header, separator, and process rows.
#[must_use]
pub fn format_process_table(processes: &[ProcessInfo], top_n: usize) -> String {
    let mut sorted: Vec<&ProcessInfo> = processes.iter().collect();
    sorted.sort_by(|a, b| b.rss_mb.cmp(&a.rss_mb));
    sorted.truncate(top_n);

    let header = format!(
        "{:<8} {:<20} {:>6} {:>10} {:<10} {:<15}",
        "PID", "NAME", "CPU%", "RAM(MB)", "STATE", "USER"
    );
    let separator = "─".repeat(header.len());

    let mut rows = vec![header, separator];

    for p in sorted {
        let name: String = p.name.chars().take(19).collect();
        let user: String = p.user.chars().take(14).collect();
        let row = format!(
            "{:<8} {:<20} {:>6.1} {:>10} {:<10} {:<15}",
            p.pid, name, p.cpu_percent, p.rss_mb, p.state, user
        );
        if p.state == ProcessState::Zombie {
            rows.push(row.red().to_string());
        } else {
            rows.push(row);
        }
    }

    rows.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::control;

    fn make_process(name: &str, rss_mb: u64, state: ProcessState) -> ProcessInfo {
        ProcessInfo {
            pid: 1000,
            ppid: 1,
            name: name.to_string(),
            cmdline: name.to_string(),
            state,
            cpu_percent: 0.0,
            rss_mb,
            vms_mb: 0,
            user: "user".to_string(),
            start_time: 0,
            open_fds: 0,
        }
    }

    #[test]
    fn sorts_by_ram_descending() {
        control::set_override(false);
        let procs = vec![
            make_process("low", 100, ProcessState::Running),
            make_process("high", 500, ProcessState::Running),
            make_process("mid", 300, ProcessState::Running),
        ];
        let table = format_process_table(&procs, 3);
        let lines: Vec<&str> = table.lines().collect();
        assert!(lines[2].contains("high"));
        assert!(lines[3].contains("mid"));
        assert!(lines[4].contains("low"));
    }

    #[test]
    fn truncates_to_top_n() {
        control::set_override(false);
        let procs = vec![
            make_process("a", 100, ProcessState::Running),
            make_process("b", 200, ProcessState::Running),
            make_process("c", 300, ProcessState::Running),
        ];
        let table = format_process_table(&procs, 2);
        // header + separator + 2 rows = 4 lines
        assert_eq!(table.lines().count(), 4);
    }

    #[test]
    fn empty_process_list() {
        control::set_override(false);
        let table = format_process_table(&[], 5);
        // header + separator only
        assert_eq!(table.lines().count(), 2);
    }

    #[test]
    fn table_has_header() {
        control::set_override(false);
        let table = format_process_table(&[], 5);
        assert!(table.contains("PID"));
        assert!(table.contains("NAME"));
        assert!(table.contains("RAM(MB)"));
    }

    #[test]
    fn zombie_process_highlighted() {
        control::set_override(false);
        let procs = vec![make_process("zombified", 100, ProcessState::Zombie)];
        let table = format_process_table(&procs, 5);
        assert!(table.contains("zombified"));
    }

    #[test]
    fn long_name_truncated() {
        control::set_override(false);
        let procs = vec![make_process(
            "very_long_process_name_that_exceeds",
            100,
            ProcessState::Running,
        )];
        let table = format_process_table(&procs, 5);
        // name truncated to 19 chars
        assert!(table.contains("very_long_process_n"));
        assert!(!table.contains("very_long_process_name_that_exceeds"));
    }
}

use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use crate::domain::entities::process::{ProcessInfo, ProcessState};
use crate::presentation::tui::event::{SortColumn, SortOrder};

/// Sort process references by the given column and order.
fn sort_processes(
    processes: &[ProcessInfo],
    column: SortColumn,
    order: SortOrder,
) -> Vec<&ProcessInfo> {
    let mut sorted: Vec<&ProcessInfo> = processes.iter().collect();

    sorted.sort_by(|a, b| {
        let cmp = match column {
            SortColumn::Pid => a.pid.cmp(&b.pid),
            SortColumn::Name => a.name.cmp(&b.name),
            SortColumn::Cpu => a
                .cpu_percent
                .partial_cmp(&b.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Memory => a.rss_mb.cmp(&b.rss_mb),
        };
        match order {
            SortOrder::Asc => cmp,
            SortOrder::Desc => cmp.reverse(),
        }
    });

    sorted
}

/// Build the header label for a column, appending the sort arrow when active.
fn header_label(title: &str, column: SortColumn, active: SortColumn, order: SortOrder) -> String {
    if column == active {
        format!("{title} {order}")
    } else {
        title.to_owned()
    }
}

/// Render a sortable process table into `area`.
pub fn render_process_list(
    frame: &mut Frame,
    processes: &[ProcessInfo],
    sort_column: SortColumn,
    sort_order: SortOrder,
    table_state: &mut TableState,
    is_focused: bool,
    area: Rect,
) {
    let sorted = sort_processes(processes, sort_column, sort_order);

    // --- Header ---
    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);

    let headers = [
        header_label("PID", SortColumn::Pid, sort_column, sort_order),
        header_label("Name", SortColumn::Name, sort_column, sort_order),
        header_label("CPU%", SortColumn::Cpu, sort_column, sort_order),
        header_label("MEM MB", SortColumn::Memory, sort_column, sort_order),
        "User".to_owned(),
        "State".to_owned(),
    ];

    let header_cells: Vec<Cell> = headers
        .iter()
        .map(|h| Cell::from(Span::styled(h.as_str(), header_style)))
        .collect();

    let header_row = Row::new(header_cells).height(1);

    // --- Rows ---
    let rows: Vec<Row> = sorted
        .iter()
        .map(|p| {
            let row_style = if p.state == ProcessState::Zombie {
                Style::default().fg(Color::Red)
            } else if p.cpu_percent > 80.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };

            let state_label = match p.state {
                ProcessState::Running => "Running",
                ProcessState::Sleeping => "Sleeping",
                ProcessState::Zombie => "Zombie",
                ProcessState::Stopped => "Stopped",
                ProcessState::Dead => "Dead",
                ProcessState::Unknown => "Unknown",
            };

            let cells = vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.name.clone()),
                Cell::from(format!("{:.1}", p.cpu_percent)),
                Cell::from(p.rss_mb.to_string()),
                Cell::from(p.user.clone()),
                Cell::from(state_label),
            ];

            Row::new(cells).style(row_style).height(1)
        })
        .collect();

    // --- Column widths ---
    let widths = [
        Constraint::Length(8),
        Constraint::Min(15),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(10),
    ];

    // --- Highlight style ---
    let highlight_style = if is_focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default().add_modifier(Modifier::DIM)
    };

    // --- Block ---
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let block = Block::default()
        .title("Processes")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let table = Table::new(rows, widths)
        .header(header_row)
        .block(block)
        .row_highlight_style(highlight_style);

    frame.render_stateful_widget(table, area, table_state);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, layout::Rect, widgets::TableState, Terminal};

    fn make_process(pid: u32, name: &str, cpu: f32, rss: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            name: name.to_string(),
            cmdline: name.to_string(),
            state: ProcessState::Running,
            cpu_percent: cpu,
            rss_mb: rss,
            vms_mb: rss * 2,
            user: "test".to_string(),
            start_time: 0,
            open_fds: 10,
        }
    }

    #[test]
    fn test_sort_by_cpu_desc() {
        let processes = vec![
            make_process(1, "low", 10.0, 100),
            make_process(2, "high", 90.0, 200),
            make_process(3, "mid", 50.0, 150),
        ];

        let sorted = sort_processes(&processes, SortColumn::Cpu, SortOrder::Desc);

        assert_eq!(sorted[0].pid, 2);
        assert_eq!(sorted[1].pid, 3);
        assert_eq!(sorted[2].pid, 1);
    }

    #[test]
    fn test_sort_by_pid_asc() {
        let processes = vec![
            make_process(30, "c", 5.0, 100),
            make_process(10, "a", 5.0, 100),
            make_process(20, "b", 5.0, 100),
        ];

        let sorted = sort_processes(&processes, SortColumn::Pid, SortOrder::Asc);

        assert_eq!(sorted[0].pid, 10);
        assert_eq!(sorted[1].pid, 20);
        assert_eq!(sorted[2].pid, 30);
    }

    #[test]
    fn test_sort_by_memory() {
        let processes = vec![
            make_process(1, "small", 5.0, 50),
            make_process(2, "large", 5.0, 500),
            make_process(3, "medium", 5.0, 200),
        ];

        let sorted_desc = sort_processes(&processes, SortColumn::Memory, SortOrder::Desc);
        assert_eq!(sorted_desc[0].rss_mb, 500);
        assert_eq!(sorted_desc[1].rss_mb, 200);
        assert_eq!(sorted_desc[2].rss_mb, 50);

        let sorted_asc = sort_processes(&processes, SortColumn::Memory, SortOrder::Asc);
        assert_eq!(sorted_asc[0].rss_mb, 50);
        assert_eq!(sorted_asc[2].rss_mb, 500);
    }

    #[test]
    fn test_render_no_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");

        let processes = vec![
            make_process(1, "init", 0.1, 10),
            make_process(100, "high-cpu", 95.0, 512),
            {
                let mut p = make_process(200, "zombie-proc", 0.0, 5);
                p.state = ProcessState::Zombie;
                p
            },
        ];

        let mut table_state = TableState::default();

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 120, 30);
                render_process_list(
                    frame,
                    &processes,
                    SortColumn::Cpu,
                    SortOrder::Desc,
                    &mut table_state,
                    true,
                    area,
                );
            })
            .expect("draw");
    }

    #[test]
    fn test_sort_by_name_asc() {
        let processes = vec![
            make_process(1, "zebra", 5.0, 100),
            make_process(2, "alpha", 5.0, 100),
            make_process(3, "mango", 5.0, 100),
        ];

        let sorted = sort_processes(&processes, SortColumn::Name, SortOrder::Asc);

        assert_eq!(sorted[0].name, "alpha");
        assert_eq!(sorted[1].name, "mango");
        assert_eq!(sorted[2].name, "zebra");
    }

    #[test]
    fn test_header_label_active_column() {
        let desc_label = header_label("CPU%", SortColumn::Cpu, SortColumn::Cpu, SortOrder::Desc);
        assert_eq!(desc_label, "CPU% ↓");

        let asc_label = header_label("CPU%", SortColumn::Cpu, SortColumn::Cpu, SortOrder::Asc);
        assert_eq!(asc_label, "CPU% ↑");
    }

    #[test]
    fn test_header_label_inactive_column() {
        let label = header_label("PID", SortColumn::Pid, SortColumn::Cpu, SortOrder::Desc);
        assert_eq!(label, "PID");
    }

    #[test]
    fn test_render_empty_list_no_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let mut table_state = TableState::default();

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 120, 30);
                render_process_list(
                    frame,
                    &[],
                    SortColumn::Cpu,
                    SortOrder::Desc,
                    &mut table_state,
                    true,
                    area,
                );
            })
            .expect("draw");
    }

    #[test]
    fn test_render_unfocused_no_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");

        let processes = vec![
            make_process(1, "init", 0.1, 10),
            make_process(2, "daemon", 2.0, 50),
        ];

        let mut table_state = TableState::default();

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 120, 30);
                render_process_list(
                    frame,
                    &processes,
                    SortColumn::Pid,
                    SortOrder::Asc,
                    &mut table_state,
                    false,
                    area,
                );
            })
            .expect("draw");
    }

    #[test]
    fn test_sort_empty_list() {
        let processes: Vec<ProcessInfo> = vec![];
        let sorted = sort_processes(&processes, SortColumn::Cpu, SortOrder::Desc);
        assert!(sorted.is_empty());
    }
}

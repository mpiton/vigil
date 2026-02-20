use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table};
use ratatui::Frame;

use crate::domain::entities::snapshot::SystemSnapshot;

fn threshold_color(value: f64, warning: f64, critical: f64) -> Color {
    if value > critical {
        Color::Red
    } else if value > warning {
        Color::Yellow
    } else {
        Color::Green
    }
}

pub fn render_dashboard(frame: &mut Frame, snapshot: &SystemSnapshot, area: Rect) {
    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    // Top row: CPU + RAM + Swap gauges
    let gauge_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(vertical_chunks[0]);

    let cpu_percent = f64::from(snapshot.cpu.global_usage_percent);
    let cpu_color = threshold_color(cpu_percent, 70.0, 90.0);
    let cpu_ratio = (cpu_percent / 100.0).clamp(0.0, 1.0);
    let cpu_gauge = Gauge::default()
        .block(Block::bordered().title("CPU"))
        .gauge_style(Style::default().fg(cpu_color))
        .ratio(cpu_ratio)
        .label(format!("{cpu_percent:.1}%"));
    frame.render_widget(cpu_gauge, gauge_chunks[0]);

    let ram_percent = snapshot.memory.usage_percent;
    let ram_color = threshold_color(ram_percent, 70.0, 90.0);
    let ram_ratio = (ram_percent / 100.0).clamp(0.0, 1.0);
    let ram_gauge = Gauge::default()
        .block(Block::bordered().title("RAM"))
        .gauge_style(Style::default().fg(ram_color))
        .ratio(ram_ratio)
        .label(format!("{ram_percent:.1}%"));
    frame.render_widget(ram_gauge, gauge_chunks[1]);

    let swap_percent = snapshot.memory.swap_percent;
    let swap_color = threshold_color(swap_percent, 70.0, 90.0);
    let swap_ratio = (swap_percent / 100.0).clamp(0.0, 1.0);
    let swap_gauge = Gauge::default()
        .block(Block::bordered().title("Swap"))
        .gauge_style(Style::default().fg(swap_color))
        .ratio(swap_ratio)
        .label(format!("{swap_percent:.1}%"));
    frame.render_widget(swap_gauge, gauge_chunks[2]);

    // Middle row: Load average
    let core_count = f64::from(snapshot.cpu.core_count);
    let warning_threshold = core_count * 0.7;
    let critical_threshold = core_count;

    let loads = [
        ("1m", snapshot.cpu.load_avg_1m),
        ("5m", snapshot.cpu.load_avg_5m),
        ("15m", snapshot.cpu.load_avg_15m),
    ];

    let mut spans = Vec::with_capacity(loads.len() * 2);
    for (idx, (label, value)) in loads.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::raw("   "));
        }
        let color = threshold_color(*value, warning_threshold, critical_threshold);
        spans.push(Span::raw(format!("{label}: ")));
        spans.push(Span::styled(
            format!("{value:.2}"),
            Style::default().fg(color),
        ));
    }

    let load_line = Line::from(spans);

    let load_paragraph = Paragraph::new(load_line).block(Block::bordered().title("Charge système"));
    frame.render_widget(load_paragraph, vertical_chunks[1]);

    // Bottom: Disk usage table
    let header_cells = ["Point de montage", "Utilisé/Total", "Usage", "Système"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().bold()));
    let header = Row::new(header_cells)
        .style(Style::default().bold())
        .height(1);

    let rows: Vec<Row<'_>> = snapshot
        .disks
        .iter()
        .map(|disk| {
            let used_gb = (disk.total_gb - disk.available_gb).max(0.0);
            let color = threshold_color(disk.usage_percent, 80.0, 90.0);
            let style = Style::default().fg(color);
            Row::new(vec![
                Cell::from(disk.mount_point.clone()).style(style),
                Cell::from(format!("{used_gb:.1}/{:.1} Go", disk.total_gb)).style(style),
                Cell::from(format!("{:.1}%", disk.usage_percent)).style(style),
                Cell::from(disk.filesystem.clone()).style(style),
            ])
        })
        .collect();

    let disk_table = Table::new(
        rows,
        [
            Constraint::Percentage(35),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(25),
        ],
    )
    .header(header)
    .block(Block::bordered().title("Disques"));

    frame.render_widget(disk_table, vertical_chunks[2]);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::disk::DiskInfo;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo, SystemSnapshot};
    use chrono::Utc;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn make_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            memory: MemoryInfo {
                total_mb: 16384,
                used_mb: 8192,
                available_mb: 8192,
                swap_total_mb: 4096,
                swap_used_mb: 512,
                usage_percent: 50.0,
                swap_percent: 12.5,
            },
            cpu: CpuInfo {
                global_usage_percent: 45.0,
                per_core_usage: vec![40.0, 50.0, 45.0, 42.0],
                core_count: 4,
                load_avg_1m: 1.2,
                load_avg_5m: 1.5,
                load_avg_15m: 1.0,
            },
            processes: vec![],
            disks: vec![
                DiskInfo {
                    mount_point: "/".to_string(),
                    total_gb: 500.0,
                    available_gb: 200.0,
                    usage_percent: 60.0,
                    filesystem: "ext4".to_string(),
                },
                DiskInfo {
                    mount_point: "/home".to_string(),
                    total_gb: 1000.0,
                    available_gb: 50.0,
                    usage_percent: 95.0,
                    filesystem: "ext4".to_string(),
                },
            ],
            journal_entries: vec![],
        }
    }

    #[test]
    fn test_threshold_color() {
        assert_eq!(threshold_color(50.0, 70.0, 90.0), Color::Green);
        assert_eq!(threshold_color(75.0, 70.0, 90.0), Color::Yellow);
        assert_eq!(threshold_color(95.0, 70.0, 90.0), Color::Red);
        assert_eq!(threshold_color(70.0, 70.0, 90.0), Color::Green);
        assert_eq!(threshold_color(90.0, 70.0, 90.0), Color::Yellow);
        assert_eq!(threshold_color(0.0, 70.0, 90.0), Color::Green);
        assert_eq!(threshold_color(100.0, 70.0, 90.0), Color::Red);
    }

    #[test]
    fn test_render_dashboard_no_panic() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let snapshot = make_snapshot();
        terminal
            .draw(|frame| {
                render_dashboard(frame, &snapshot, frame.area());
            })
            .expect("draw");
    }

    #[test]
    fn test_render_dashboard_empty_disks() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let mut snapshot = make_snapshot();
        snapshot.disks.clear();
        terminal
            .draw(|frame| {
                render_dashboard(frame, &snapshot, frame.area());
            })
            .expect("draw with no disks");
    }

    #[test]
    fn test_render_dashboard_high_usage() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let mut snapshot = make_snapshot();
        snapshot.cpu.global_usage_percent = 95.0;
        snapshot.memory.usage_percent = 92.0;
        snapshot.memory.swap_percent = 88.0;
        snapshot.cpu.load_avg_1m = 5.0;
        terminal
            .draw(|frame| {
                render_dashboard(frame, &snapshot, frame.area());
            })
            .expect("draw with high usage");
    }
}

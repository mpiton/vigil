use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use anyhow::Context;
use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, ListState, Paragraph, TableState};
use ratatui::{Frame, Terminal};

use crate::domain::entities::alert::Alert;
use crate::domain::entities::snapshot::SystemSnapshot;
use crate::domain::ports::collector::SystemCollector;
use crate::domain::ports::store::AlertStore;
use crate::domain::value_objects::thresholds::ThresholdSet;
use crate::presentation::tui::event::{ActivePanel, SortColumn, SortOrder};
use crate::presentation::tui::widgets::alert_panel::render_alert_panel;
use crate::presentation::tui::widgets::dashboard::render_dashboard;
use crate::presentation::tui::widgets::process_list::render_process_list;

const MAX_RECENT_ALERTS: usize = 50;

struct App<'a> {
    collector: &'a dyn SystemCollector,
    alert_store: &'a dyn AlertStore,

    snapshot: Option<SystemSnapshot>,
    alerts: Vec<Alert>,

    active_panel: ActivePanel,
    sort_column: SortColumn,
    sort_order: SortOrder,
    table_state: TableState,
    alert_list_state: ListState,

    should_quit: bool,
    tick_rate: Duration,
}

impl<'a> App<'a> {
    #[must_use]
    fn new(
        collector: &'a dyn SystemCollector,
        alert_store: &'a dyn AlertStore,
        interval_secs: u64,
    ) -> Self {
        Self {
            collector,
            alert_store,
            snapshot: None,
            alerts: Vec::new(),
            active_panel: ActivePanel::default(),
            sort_column: SortColumn::default(),
            sort_order: SortOrder::default(),
            table_state: TableState::default(),
            alert_list_state: ListState::default(),
            should_quit: false,
            tick_rate: Duration::from_secs(interval_secs.max(1)),
        }
    }

    fn refresh_data(&mut self) {
        if let Ok(snapshot) = self.collector.collect() {
            self.snapshot = Some(snapshot);
        }
        if let Ok(alerts) = self.alert_store.get_recent_alerts(MAX_RECENT_ALERTS) {
            self.alerts = alerts;
        }
        // Clamp selection indices to new data bounds
        self.clamp_selections();
    }

    fn clamp_selections(&mut self) {
        let process_count = self.snapshot.as_ref().map_or(0, |s| s.processes.len());
        if let Some(sel) = self.table_state.selected() {
            if process_count == 0 {
                self.table_state.select(None);
            } else if sel >= process_count {
                self.table_state.select(Some(process_count - 1));
            }
        }
        let alert_count = self.alerts.len();
        if let Some(sel) = self.alert_list_state.selected() {
            if alert_count == 0 {
                self.alert_list_state.select(None);
            } else if sel >= alert_count {
                self.alert_list_state.select(Some(alert_count - 1));
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab => self.active_panel = self.active_panel.next(),
            KeyCode::BackTab => self.active_panel = self.active_panel.prev(),
            KeyCode::Char('j') | KeyCode::Down => self.scroll_down(),
            KeyCode::Char('k') | KeyCode::Up => self.scroll_up(),
            KeyCode::Char('s') => {
                if self.active_panel == ActivePanel::Processes {
                    self.sort_column = self.sort_column.next();
                }
            }
            KeyCode::Char('o') => {
                if self.active_panel == ActivePanel::Processes {
                    self.sort_order = self.sort_order.toggle();
                }
            }
            KeyCode::Char('r') => self.refresh_data(),
            _ => {}
        }
    }

    fn scroll_down(&mut self) {
        match self.active_panel {
            ActivePanel::Dashboard => {}
            ActivePanel::Processes => {
                let count = self.snapshot.as_ref().map_or(0, |s| s.processes.len());
                if count > 0 {
                    let i = self.table_state.selected().map_or(0, |i| {
                        if i >= count - 1 {
                            0
                        } else {
                            i + 1
                        }
                    });
                    self.table_state.select(Some(i));
                }
            }
            ActivePanel::Alerts => {
                let count = self.alerts.len();
                if count > 0 {
                    let i = self.alert_list_state.selected().map_or(0, |i| {
                        if i >= count - 1 {
                            0
                        } else {
                            i + 1
                        }
                    });
                    self.alert_list_state.select(Some(i));
                }
            }
        }
    }

    fn scroll_up(&mut self) {
        match self.active_panel {
            ActivePanel::Dashboard => {}
            ActivePanel::Processes => {
                let count = self.snapshot.as_ref().map_or(0, |s| s.processes.len());
                if count > 0 {
                    let i = self.table_state.selected().map_or(count - 1, |i| {
                        if i == 0 {
                            count - 1
                        } else {
                            i - 1
                        }
                    });
                    self.table_state.select(Some(i));
                }
            }
            ActivePanel::Alerts => {
                let count = self.alerts.len();
                if count > 0 {
                    let i = self.alert_list_state.selected().map_or(count - 1, |i| {
                        if i == 0 {
                            count - 1
                        } else {
                            i - 1
                        }
                    });
                    self.alert_list_state.select(Some(i));
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();

        let [header_area, body_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        self.render_header(frame, header_area);

        let [dashboard_area, process_area, alert_area] = Layout::vertical([
            Constraint::Length(9),
            Constraint::Fill(1),
            Constraint::Length(10),
        ])
        .areas(body_area);

        if let Some(ref snapshot) = self.snapshot {
            render_dashboard(frame, snapshot, dashboard_area);
            render_process_list(
                frame,
                &snapshot.processes,
                self.sort_column,
                self.sort_order,
                &mut self.table_state,
                self.active_panel == ActivePanel::Processes,
                process_area,
            );
        } else {
            let loading = Paragraph::new("Loading data...")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::bordered().title("Dashboard"));
            frame.render_widget(loading, dashboard_area);
            let loading_proc = Paragraph::new("Loading data...")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::bordered().title("Processes"));
            frame.render_widget(loading_proc, process_area);
        }

        render_alert_panel(
            frame,
            &self.alerts,
            &mut self.alert_list_state,
            self.active_panel == ActivePanel::Alerts,
            alert_area,
        );

        self.render_status_bar(frame, status_area);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let timestamp = self.snapshot.as_ref().map_or_else(
            || "--:--:--".to_string(),
            |s| s.timestamp.format("%H:%M:%S").to_string(),
        );

        let header = Line::from(vec![
            Span::styled(
                " VIGIL ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("│ "),
            Span::styled(
                format!("[{}]", self.active_panel),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" │ "),
            Span::styled(timestamp, Style::default().fg(Color::DarkGray)),
        ]);

        frame.render_widget(Paragraph::new(header), area);
    }

    #[allow(clippy::unused_self)]
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let key_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        let bar = Line::from(vec![
            Span::styled(" q", key_style),
            Span::raw(":quit "),
            Span::styled("Tab", key_style),
            Span::raw(":panel "),
            Span::styled("j/k", key_style),
            Span::raw(":nav "),
            Span::styled("s", key_style),
            Span::raw(":sort "),
            Span::styled("o", key_style),
            Span::raw(":order "),
            Span::styled("r", key_style),
            Span::raw(":refresh"),
        ]);

        frame.render_widget(
            Paragraph::new(bar).style(Style::default().bg(Color::DarkGray)),
            area,
        );
    }
}

/// Restore the terminal to its normal state.
fn restore_terminal() {
    if let Err(e) = disable_raw_mode() {
        eprintln!("Failed to disable raw mode: {e}");
    }
    if let Err(e) = execute!(io::stdout(), LeaveAlternateScreen) {
        eprintln!("Failed to leave alternate screen: {e}");
    }
}

/// Launch the interactive TUI dashboard.
///
/// # Errors
///
/// Returns an error if terminal setup, rendering, or event handling fails.
pub fn run_tui(
    collector: &dyn SystemCollector,
    alert_store: &dyn AlertStore,
    _thresholds: &ThresholdSet,
    interval_secs: u64,
) -> anyhow::Result<()> {
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();
    if let Err(e) = execute!(stdout, EnterAlternateScreen) {
        // Raw mode was enabled but alternate screen failed — restore before returning
        let _ = disable_raw_mode();
        return Err(e).context("Failed to enter alternate screen");
    }

    // Install panic hook so terminal is restored even on panic
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    let mut app = App::new(collector, alert_store, interval_secs);
    app.refresh_data();

    let result = run_app_loop(&mut terminal, &mut app);

    // Restore terminal on normal exit
    restore_terminal();
    let _ = terminal.show_cursor();

    // Restore the default panic hook
    let _ = std::panic::take_hook();

    result
}

fn run_app_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App<'_>,
) -> anyhow::Result<()> {
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| app.draw(frame))?;

        let timeout = app.tick_rate.saturating_sub(last_tick.elapsed());

        if event::poll(timeout)? {
            if let CrosstermEvent::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key);
                }
            }
        }

        if last_tick.elapsed() >= app.tick_rate {
            app.refresh_data();
            last_tick = Instant::now();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::entities::alert::Alert;
    use crate::domain::entities::disk::DiskInfo;
    use crate::domain::entities::snapshot::{CpuInfo, MemoryInfo};
    use crate::domain::ports::collector::CollectionError;
    use crate::domain::ports::store::StoreError;
    use crate::domain::value_objects::severity::Severity;
    use chrono::Utc;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::backend::TestBackend;

    struct MockCollector {
        snapshot: SystemSnapshot,
    }

    impl SystemCollector for MockCollector {
        fn collect(&self) -> Result<SystemSnapshot, CollectionError> {
            Ok(self.snapshot.clone())
        }
    }

    struct MockAlertStore {
        alerts: Vec<Alert>,
    }

    impl AlertStore for MockAlertStore {
        fn save_alert(&self, _alert: &Alert) -> Result<(), StoreError> {
            Ok(())
        }
        fn get_alerts(&self) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.clone())
        }
        fn get_recent_alerts(&self, _count: usize) -> Result<Vec<Alert>, StoreError> {
            Ok(self.alerts.clone())
        }
        fn get_alerts_since(
            &self,
            _since: chrono::DateTime<Utc>,
        ) -> Result<Vec<Alert>, StoreError> {
            Ok(vec![])
        }
    }

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

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
                per_core_usage: vec![40.0, 50.0],
                core_count: 2,
                load_avg_1m: 1.2,
                load_avg_5m: 1.5,
                load_avg_15m: 1.0,
            },
            processes: vec![],
            disks: vec![DiskInfo {
                mount_point: "/".to_string(),
                total_gb: 500.0,
                available_gb: 200.0,
                usage_percent: 60.0,
                filesystem: "ext4".to_string(),
            }],
            journal_entries: vec![],
        }
    }

    fn make_alert(severity: Severity) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: "Test alert".to_string(),
            details: "Details".to_string(),
            suggested_actions: vec![],
        }
    }

    fn make_app<'a>(collector: &'a MockCollector, store: &'a MockAlertStore) -> App<'a> {
        App::new(collector, store, 5)
    }

    #[test]
    fn app_default_state() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let app = make_app(&collector, &store);

        assert_eq!(app.active_panel, ActivePanel::Dashboard);
        assert_eq!(app.sort_column, SortColumn::Cpu);
        assert_eq!(app.sort_order, SortOrder::Desc);
        assert!(!app.should_quit);
        assert!(app.snapshot.is_none());
    }

    #[test]
    fn handle_quit_key() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);

        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn handle_esc_quits() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);

        app.handle_key(make_key(KeyCode::Esc));
        assert!(app.should_quit);
    }

    #[test]
    fn handle_tab_cycles_panels() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);

        assert_eq!(app.active_panel, ActivePanel::Dashboard);
        app.handle_key(make_key(KeyCode::Tab));
        assert_eq!(app.active_panel, ActivePanel::Processes);
        app.handle_key(make_key(KeyCode::Tab));
        assert_eq!(app.active_panel, ActivePanel::Alerts);
        app.handle_key(make_key(KeyCode::Tab));
        assert_eq!(app.active_panel, ActivePanel::Dashboard);
    }

    #[test]
    fn handle_sort_change() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);
        app.active_panel = ActivePanel::Processes;

        assert_eq!(app.sort_column, SortColumn::Cpu);
        app.handle_key(make_key(KeyCode::Char('s')));
        assert_eq!(app.sort_column, SortColumn::Memory);

        assert_eq!(app.sort_order, SortOrder::Desc);
        app.handle_key(make_key(KeyCode::Char('o')));
        assert_eq!(app.sort_order, SortOrder::Asc);
    }

    #[test]
    fn sort_keys_ignored_outside_process_panel() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);
        app.active_panel = ActivePanel::Dashboard;

        let original_col = app.sort_column;
        app.handle_key(make_key(KeyCode::Char('s')));
        assert_eq!(app.sort_column, original_col);
    }

    #[test]
    fn refresh_data_populates_state() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::High)],
        };
        let mut app = make_app(&collector, &store);

        assert!(app.snapshot.is_none());
        assert!(app.alerts.is_empty());

        app.refresh_data();

        assert!(app.snapshot.is_some());
        assert_eq!(app.alerts.len(), 1);
    }

    #[test]
    fn draw_no_panic_with_data() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::Critical), make_alert(Severity::Low)],
        };
        let mut app = make_app(&collector, &store);
        app.refresh_data();

        terminal
            .draw(|frame| app.draw(frame))
            .expect("draw with data");
    }

    #[test]
    fn draw_no_panic_without_data() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);

        terminal
            .draw(|frame| app.draw(frame))
            .expect("draw without data");
    }

    #[test]
    fn scroll_down_wraps_around() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::High), make_alert(Severity::Low)],
        };
        let mut app = make_app(&collector, &store);
        app.refresh_data();
        app.active_panel = ActivePanel::Alerts;

        // Scroll down from unselected → select 0
        app.scroll_down();
        assert_eq!(app.alert_list_state.selected(), Some(0));

        // Scroll down → select 1
        app.scroll_down();
        assert_eq!(app.alert_list_state.selected(), Some(1));

        // Scroll down wraps → select 0
        app.scroll_down();
        assert_eq!(app.alert_list_state.selected(), Some(0));
    }

    #[test]
    fn scroll_up_selects_last_first() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::High), make_alert(Severity::Low)],
        };
        let mut app = make_app(&collector, &store);
        app.refresh_data();
        app.active_panel = ActivePanel::Alerts;

        // Scroll up from unselected → select last (1)
        app.scroll_up();
        assert_eq!(app.alert_list_state.selected(), Some(1));

        // Scroll up → select 0
        app.scroll_up();
        assert_eq!(app.alert_list_state.selected(), Some(0));

        // Scroll up wraps → select last (1)
        app.scroll_up();
        assert_eq!(app.alert_list_state.selected(), Some(1));
    }

    #[test]
    fn clamp_selections_after_refresh() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::High)],
        };
        let mut app = make_app(&collector, &store);
        app.refresh_data();
        app.active_panel = ActivePanel::Alerts;

        // Select index 0, then refresh with data that still has 1 alert → stays
        app.alert_list_state.select(Some(0));
        app.refresh_data();
        assert_eq!(app.alert_list_state.selected(), Some(0));

        // Set index beyond bounds, refresh should clamp
        app.alert_list_state.select(Some(99));
        app.clamp_selections();
        assert_eq!(app.alert_list_state.selected(), Some(0));
    }

    #[test]
    fn interval_clamped_to_minimum() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let app = App::new(&collector, &store, 0);
        assert_eq!(app.tick_rate, Duration::from_secs(1));
    }

    #[test]
    fn handle_backtab_cycles_panels_backward() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);

        assert_eq!(app.active_panel, ActivePanel::Dashboard);
        app.handle_key(make_key(KeyCode::BackTab));
        assert_eq!(app.active_panel, ActivePanel::Alerts);
        app.handle_key(make_key(KeyCode::BackTab));
        assert_eq!(app.active_panel, ActivePanel::Processes);
        app.handle_key(make_key(KeyCode::BackTab));
        assert_eq!(app.active_panel, ActivePanel::Dashboard);
    }

    #[test]
    fn handle_j_k_keys_scroll() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::High), make_alert(Severity::Low)],
        };
        let mut app = make_app(&collector, &store);
        app.refresh_data();
        app.active_panel = ActivePanel::Alerts;

        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.alert_list_state.selected(), Some(0));

        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.alert_list_state.selected(), Some(1));

        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.alert_list_state.selected(), Some(0));
    }

    #[test]
    fn handle_down_up_keys_scroll() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore {
            alerts: vec![make_alert(Severity::High), make_alert(Severity::Low)],
        };
        let mut app = make_app(&collector, &store);
        app.refresh_data();
        app.active_panel = ActivePanel::Alerts;

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.alert_list_state.selected(), Some(0));

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.alert_list_state.selected(), Some(1));

        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.alert_list_state.selected(), Some(0));
    }

    #[test]
    fn handle_r_refreshes_data() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);

        assert!(app.snapshot.is_none());
        app.handle_key(make_key(KeyCode::Char('r')));
        assert!(app.snapshot.is_some());
    }

    #[test]
    fn scroll_on_dashboard_is_noop() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);
        app.refresh_data();
        app.active_panel = ActivePanel::Dashboard;

        app.scroll_down();
        assert_eq!(app.table_state.selected(), None);
        assert_eq!(app.alert_list_state.selected(), None);

        app.scroll_up();
        assert_eq!(app.table_state.selected(), None);
        assert_eq!(app.alert_list_state.selected(), None);
    }

    #[test]
    fn scroll_process_panel_wraps() {
        use crate::domain::entities::process::{ProcessInfo, ProcessState};

        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);
        app.refresh_data();

        let mut snapshot = make_snapshot();
        snapshot.processes = vec![
            ProcessInfo {
                pid: 1,
                ppid: 0,
                name: "init".to_string(),
                cmdline: "init".to_string(),
                state: ProcessState::Running,
                cpu_percent: 1.0,
                rss_mb: 10,
                vms_mb: 20,
                user: "root".to_string(),
                start_time: 0,
                open_fds: 5,
            },
            ProcessInfo {
                pid: 2,
                ppid: 1,
                name: "bash".to_string(),
                cmdline: "bash".to_string(),
                state: ProcessState::Running,
                cpu_percent: 2.0,
                rss_mb: 50,
                vms_mb: 100,
                user: "test".to_string(),
                start_time: 0,
                open_fds: 10,
            },
        ];
        app.snapshot = Some(snapshot);
        app.active_panel = ActivePanel::Processes;

        app.scroll_down();
        assert_eq!(app.table_state.selected(), Some(0));

        app.scroll_down();
        assert_eq!(app.table_state.selected(), Some(1));

        app.scroll_down();
        assert_eq!(app.table_state.selected(), Some(0));

        app.table_state.select(None);
        app.scroll_up();
        assert_eq!(app.table_state.selected(), Some(1));
    }

    #[test]
    fn scroll_on_empty_data_is_noop() {
        let collector = MockCollector {
            snapshot: make_snapshot(),
        };
        let store = MockAlertStore { alerts: vec![] };
        let mut app = make_app(&collector, &store);
        app.active_panel = ActivePanel::Processes;

        assert!(app.snapshot.is_none());

        app.scroll_down();
        assert_eq!(app.table_state.selected(), None);

        app.scroll_up();
        assert_eq!(app.table_state.selected(), None);
    }
}

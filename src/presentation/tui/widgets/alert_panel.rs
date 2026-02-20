use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState},
    Frame,
};

use crate::domain::entities::alert::Alert;
use crate::domain::value_objects::severity::Severity;

const fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
    }
}

fn severity_style(severity: Severity) -> Style {
    let color = severity_color(severity);
    let style = Style::default().fg(color);
    if matches!(severity, Severity::Critical) {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

pub fn render_alert_panel(
    frame: &mut Frame,
    alerts: &[Alert],
    list_state: &mut ListState,
    is_focused: bool,
    area: Rect,
) {
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .title("Alertes")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color));

    let highlight_style = if is_focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default().add_modifier(Modifier::DIM)
    };

    let items: Vec<ListItem<'_>> = if alerts.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "Aucune alerte active",
            Style::default().fg(Color::Green),
        )))]
    } else {
        alerts
            .iter()
            .map(|alert| {
                let style = severity_style(alert.severity);
                let line1 = Line::from(vec![Span::styled(
                    format!(
                        "{} [{}] {}",
                        alert.severity.emoji(),
                        alert.severity,
                        alert.title
                    ),
                    style,
                )]);
                let timestamp = alert.timestamp.format("%H:%M:%S").to_string();
                let line2 = Line::from(vec![Span::styled(
                    format!("  {} — {}", timestamp, alert.details),
                    Style::default().add_modifier(Modifier::DIM),
                )]);
                ListItem::new(vec![line1, line2])
            })
            .collect()
    };

    let list = List::new(items)
        .block(block)
        .highlight_style(highlight_style)
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, area, list_state);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ratatui::{backend::TestBackend, Terminal};

    fn make_alert(severity: Severity, title: &str) -> Alert {
        Alert {
            timestamp: Utc::now(),
            severity,
            rule: "test_rule".to_string(),
            title: title.to_string(),
            details: "Détails du test".to_string(),
            suggested_actions: vec![],
        }
    }

    #[test]
    fn test_severity_color_mapping() {
        assert_eq!(severity_color(Severity::Critical), Color::Red);
        assert_eq!(severity_color(Severity::High), Color::LightRed);
        assert_eq!(severity_color(Severity::Medium), Color::Yellow);
        assert_eq!(severity_color(Severity::Low), Color::Cyan);
    }

    #[test]
    fn test_render_with_alerts_no_panic() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let alerts = vec![
            make_alert(Severity::Critical, "CPU critique"),
            make_alert(Severity::High, "Mémoire élevée"),
            make_alert(Severity::Medium, "Swap utilisé"),
            make_alert(Severity::Low, "Processus zombie"),
        ];
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        terminal
            .draw(|frame| {
                render_alert_panel(frame, &alerts, &mut list_state, true, frame.area());
            })
            .expect("draw");
    }

    #[test]
    fn test_render_empty_alerts_no_panic() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let alerts: Vec<Alert> = vec![];
        let mut list_state = ListState::default();
        terminal
            .draw(|frame| {
                render_alert_panel(frame, &alerts, &mut list_state, false, frame.area());
            })
            .expect("draw");
    }

    #[test]
    fn test_severity_style_critical_is_bold() {
        assert_eq!(
            severity_style(Severity::Critical),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        );
    }

    #[test]
    fn test_severity_style_non_critical_no_bold() {
        assert_eq!(
            severity_style(Severity::High),
            Style::default().fg(Color::LightRed)
        );
        assert_eq!(
            severity_style(Severity::Medium),
            Style::default().fg(Color::Yellow)
        );
        assert_eq!(
            severity_style(Severity::Low),
            Style::default().fg(Color::Cyan)
        );
    }

    #[test]
    fn test_render_focused_vs_unfocused() {
        let alerts = vec![
            make_alert(Severity::Critical, "CPU critique"),
            make_alert(Severity::Low, "Alerte basse"),
        ];
        let mut list_state = ListState::default();

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("terminal focused");
        terminal
            .draw(|frame| {
                render_alert_panel(frame, &alerts, &mut list_state, true, frame.area());
            })
            .expect("draw focused");

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("terminal unfocused");
        terminal
            .draw(|frame| {
                render_alert_panel(frame, &alerts, &mut list_state, false, frame.area());
            })
            .expect("draw unfocused");
    }
}

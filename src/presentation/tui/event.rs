use std::fmt;

/// Events handled by the TUI application loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Periodic tick for data refresh.
    Tick,
    /// Keyboard input.
    Key(crossterm::event::KeyEvent),
    /// Terminal resize.
    Resize(u16, u16),
}

/// Which panel currently has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivePanel {
    #[default]
    Dashboard,
    Processes,
    Alerts,
}

impl ActivePanel {
    /// Cycle to the next panel.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Dashboard => Self::Processes,
            Self::Processes => Self::Alerts,
            Self::Alerts => Self::Dashboard,
        }
    }

    /// Cycle to the previous panel.
    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Dashboard => Self::Alerts,
            Self::Processes => Self::Dashboard,
            Self::Alerts => Self::Processes,
        }
    }
}

impl fmt::Display for ActivePanel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dashboard => write!(f, "Tableau de bord"),
            Self::Processes => write!(f, "Processus"),
            Self::Alerts => write!(f, "Alertes"),
        }
    }
}

/// Column used for sorting the process list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    Pid,
    Name,
    #[default]
    Cpu,
    Memory,
}

impl SortColumn {
    /// Cycle to the next sort column.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Pid => Self::Name,
            Self::Name => Self::Cpu,
            Self::Cpu => Self::Memory,
            Self::Memory => Self::Pid,
        }
    }
}

impl fmt::Display for SortColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pid => write!(f, "PID"),
            Self::Name => write!(f, "Nom"),
            Self::Cpu => write!(f, "CPU"),
            Self::Memory => write!(f, "Mémoire"),
        }
    }
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

impl SortOrder {
    /// Toggle the sort direction.
    #[must_use]
    pub const fn toggle(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }
}

impl fmt::Display for SortOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asc => write!(f, "↑"),
            Self::Desc => write!(f, "↓"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn active_panel_cycles_forward() {
        assert_eq!(ActivePanel::Dashboard.next(), ActivePanel::Processes);
        assert_eq!(ActivePanel::Processes.next(), ActivePanel::Alerts);
        assert_eq!(ActivePanel::Alerts.next(), ActivePanel::Dashboard);
    }

    #[test]
    fn active_panel_cycles_backward() {
        assert_eq!(ActivePanel::Dashboard.prev(), ActivePanel::Alerts);
        assert_eq!(ActivePanel::Processes.prev(), ActivePanel::Dashboard);
        assert_eq!(ActivePanel::Alerts.prev(), ActivePanel::Processes);
    }

    #[test]
    fn sort_column_cycles() {
        assert_eq!(SortColumn::Pid.next(), SortColumn::Name);
        assert_eq!(SortColumn::Name.next(), SortColumn::Cpu);
        assert_eq!(SortColumn::Cpu.next(), SortColumn::Memory);
        assert_eq!(SortColumn::Memory.next(), SortColumn::Pid);
    }

    #[test]
    fn sort_order_toggles() {
        assert_eq!(SortOrder::Asc.toggle(), SortOrder::Desc);
        assert_eq!(SortOrder::Desc.toggle(), SortOrder::Asc);
    }

    #[test]
    fn active_panel_display_french() {
        assert_eq!(ActivePanel::Dashboard.to_string(), "Tableau de bord");
        assert_eq!(ActivePanel::Processes.to_string(), "Processus");
        assert_eq!(ActivePanel::Alerts.to_string(), "Alertes");
    }

    #[test]
    fn sort_column_display() {
        assert_eq!(SortColumn::Cpu.to_string(), "CPU");
        assert_eq!(SortColumn::Memory.to_string(), "Mémoire");
    }

    #[test]
    fn sort_order_display() {
        assert_eq!(SortOrder::Asc.to_string(), "↑");
        assert_eq!(SortOrder::Desc.to_string(), "↓");
    }

    #[test]
    fn default_values() {
        assert_eq!(ActivePanel::default(), ActivePanel::Dashboard);
        assert_eq!(SortColumn::default(), SortColumn::Cpu);
        assert_eq!(SortOrder::default(), SortOrder::Desc);
    }
}

use serde::{Deserialize, Serialize};

/// Information about a running process
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub state: ProcessState,
    pub cpu_percent: f32,
    pub rss_mb: u64,
    pub vms_mb: u64,
    pub user: String,
    pub start_time: u64,
    pub open_fds: usize,
}

/// State of a process as reported by the OS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProcessState {
    Running,
    Sleeping,
    Zombie,
    Stopped,
    Dead,
    Unknown,
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "Running"),
            Self::Sleeping => write!(f, "Sleeping"),
            Self::Zombie => write!(f, "Zombie"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Dead => write!(f, "Dead"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn process_state_display() {
        assert_eq!(ProcessState::Running.to_string(), "Running");
        assert_eq!(ProcessState::Sleeping.to_string(), "Sleeping");
        assert_eq!(ProcessState::Zombie.to_string(), "Zombie");
        assert_eq!(ProcessState::Stopped.to_string(), "Stopped");
        assert_eq!(ProcessState::Dead.to_string(), "Dead");
        assert_eq!(ProcessState::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn process_state_equality() {
        assert_eq!(ProcessState::Running, ProcessState::Running);
        assert_ne!(ProcessState::Running, ProcessState::Zombie);
    }

    #[test]
    fn process_info_serde_roundtrip() {
        let process = ProcessInfo {
            pid: 1234,
            ppid: 1,
            name: "test".to_string(),
            cmdline: "/usr/bin/test".to_string(),
            state: ProcessState::Running,
            cpu_percent: 5.5,
            rss_mb: 100,
            vms_mb: 200,
            user: "root".to_string(),
            start_time: 1000,
            open_fds: 10,
        };
        let json = serde_json::to_string(&process).expect("serialize");
        let deserialized: ProcessInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.pid, 1234);
        assert_eq!(deserialized.state, ProcessState::Running);
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete system snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: DateTime<Utc>,
    pub memory: MemoryInfo,
    pub cpu: CpuInfo,
    pub processes: Vec<ProcessInfo>,
    pub disks: Vec<DiskInfo>,
    pub journal_entries: Vec<JournalEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub swap_total_mb: u64,
    pub swap_used_mb: u64,
    pub usage_percent: f64,
    pub swap_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub global_usage_percent: f32,
    pub per_core_usage: Vec<f32>,
    pub core_count: usize,
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub load_avg_15m: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mount_point: String,
    pub total_gb: f64,
    pub available_gb: f64,
    pub usage_percent: f64,
    pub filesystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub timestamp: DateTime<Utc>,
    pub priority: u8,
    pub unit: String,
    pub message: String,
}

// --- Alert types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub rule: String,
    pub title: String,
    pub details: String,
    pub suggested_actions: Vec<SuggestedAction>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    pub fn emoji(&self) -> &str {
        match self {
            Self::Low => "ℹ️",
            Self::Medium => "⚠️",
            Self::High => "🔶",
            Self::Critical => "🔴",
        }
    }

    pub fn color(&self) -> &str {
        match self {
            Self::Low => "blue",
            Self::Medium => "yellow",
            Self::High => "red",
            Self::Critical => "bright red",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedAction {
    pub description: String,
    pub command: String,
    pub risk: ActionRisk,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionRisk {
    Safe,
    Moderate,
    Dangerous,
}

impl std::fmt::Display for ActionRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Safe => write!(f, "safe"),
            Self::Moderate => write!(f, "moderate"),
            Self::Dangerous => write!(f, "dangerous"),
        }
    }
}

// --- AI response types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDiagnostic {
    pub diagnostic: String,
    pub severity: String,
    pub actions: Vec<AiAction>,
    pub prevention: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub target: String,
    pub command: String,
    pub risk: String,
    pub explanation: String,
}

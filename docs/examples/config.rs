use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub thresholds: ThresholdConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub notifications: NotificationConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_mode")]
    pub mode: OperationMode,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_language")]
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
    Observe,
    Suggest,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    #[serde(default = "default_ram_warn")]
    pub ram_warn_percent: f64,
    #[serde(default = "default_ram_critical")]
    pub ram_critical_percent: f64,
    #[serde(default = "default_swap_warn")]
    pub swap_warn_percent: f64,
    #[serde(default = "default_cpu_load_factor")]
    pub cpu_load_factor: f64,
    #[serde(default = "default_disk_min_free")]
    pub disk_min_free_percent: f64,
    #[serde(default = "default_max_duplicates")]
    pub max_duplicate_processes: usize,
    #[serde(default = "default_zombie_timeout")]
    pub zombie_timeout_secs: u64,
    #[serde(default = "default_temp_cpu")]
    pub temperature_cpu_max: f32,
    #[serde(default = "default_temp_gpu")]
    pub temperature_gpu_max: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default = "default_true")]
    pub desktop: bool,
    #[serde(default = "default_true")]
    pub terminal: bool,
    #[serde(default)]
    pub log_file: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default = "default_ignore_commands")]
    pub ignore_commands: Vec<String>,
    #[serde(default = "default_protected_commands")]
    pub protected_commands: Vec<String>,
}

// --- Defaults ---

fn default_mode() -> OperationMode {
    OperationMode::Suggest
}
fn default_interval() -> u64 {
    5
}
fn default_language() -> String {
    "fr".into()
}
fn default_ram_warn() -> f64 {
    80.0
}
fn default_ram_critical() -> f64 {
    90.0
}
fn default_swap_warn() -> f64 {
    40.0
}
fn default_cpu_load_factor() -> f64 {
    2.0
}
fn default_disk_min_free() -> f64 {
    10.0
}
fn default_max_duplicates() -> usize {
    5
}
fn default_zombie_timeout() -> u64 {
    300
}
fn default_temp_cpu() -> f32 {
    85.0
}
fn default_temp_gpu() -> f32 {
    80.0
}
fn default_true() -> bool {
    true
}
fn default_provider() -> String {
    "anthropic".into()
}
fn default_model() -> String {
    "claude-sonnet-4-20250514".into()
}
fn default_api_key_env() -> String {
    "ANTHROPIC_API_KEY".into()
}
fn default_max_tokens() -> u32 {
    1024
}
fn default_cooldown() -> u64 {
    60
}
fn default_ignore_commands() -> Vec<String> {
    vec![
        "systemd".into(),
        "dbus-daemon".into(),
        "Xorg".into(),
        "Xwayland".into(),
    ]
}
fn default_protected_commands() -> Vec<String> {
    vec![
        "sshd".into(),
        "systemd".into(),
        "dbus-daemon".into(),
        "NetworkManager".into(),
    ]
}

// --- Impls ---

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            thresholds: ThresholdConfig::default(),
            ai: AiConfig::default(),
            notifications: NotificationConfig::default(),
            allowlist: AllowlistConfig::default(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            interval_secs: default_interval(),
            language: default_language(),
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            ram_warn_percent: default_ram_warn(),
            ram_critical_percent: default_ram_critical(),
            swap_warn_percent: default_swap_warn(),
            cpu_load_factor: default_cpu_load_factor(),
            disk_min_free_percent: default_disk_min_free(),
            max_duplicate_processes: default_max_duplicates(),
            zombie_timeout_secs: default_zombie_timeout(),
            temperature_cpu_max: default_temp_cpu(),
            temperature_gpu_max: default_temp_gpu(),
        }
    }
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            provider: default_provider(),
            model: default_model(),
            api_key_env: default_api_key_env(),
            max_tokens: default_max_tokens(),
            cooldown_secs: default_cooldown(),
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            desktop: default_true(),
            terminal: default_true(),
            log_file: None,
            webhook_url: None,
        }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            ignore_commands: default_ignore_commands(),
            protected_commands: default_protected_commands(),
        }
    }
}

impl Config {
    /// Load config from default path or create default config file
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if path.exists() {
            let content = std::fs::read_to_string(&path).context("Failed to read config file")?;
            toml::from_str(&content).context("Failed to parse config file")
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Load from a specific path
    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).context("Failed to read config file")?;
        toml::from_str(&content).context("Failed to parse config file")
    }

    /// Save config to default path
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create config directory")?;
        }
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(&path, content).context("Failed to write config file")?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().context("Could not determine config directory")?;
        Ok(config_dir.join("vigil").join("config.toml"))
    }
}

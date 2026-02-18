use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::domain::value_objects::thresholds::ThresholdSet;
use crate::domain::value_objects::OperationMode;

/// Top-level application configuration loaded from TOML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
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
    #[serde(default)]
    pub database: DatabaseConfig,
}

/// General settings: operation mode, polling interval, language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_mode")]
    pub mode: OperationMode,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_language")]
    pub language: String,
}

/// Alert thresholds for system resource monitoring.
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

/// AI analysis provider settings (claude-cli, ollama, or noop).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
    #[serde(default)]
    pub ollama_url: Option<String>,
}

/// Notification channels: desktop, terminal, log file, webhook.
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

/// Allowlisted commands to ignore or protect from termination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default = "default_ignore_commands")]
    pub ignore_commands: Vec<String>,
    #[serde(default = "default_protected_commands")]
    pub protected_commands: Vec<String>,
}

/// Database storage path (tilde-expanded at point of use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_database_path")]
    pub path: String,
}

// --- Defaults ---

// NOTE: Intentionally returns Suggest (not Observe) — the domain OperationMode::default()
// returns Observe for safety, but the config layer defaults to Suggest for better UX.
const fn default_mode() -> OperationMode {
    OperationMode::Suggest
}

const fn default_interval() -> u64 {
    5
}

fn default_language() -> String {
    "fr".into()
}

const fn default_ram_warn() -> f64 {
    80.0
}

const fn default_ram_critical() -> f64 {
    90.0
}

const fn default_swap_warn() -> f64 {
    40.0
}

const fn default_cpu_load_factor() -> f64 {
    2.0
}

const fn default_disk_min_free() -> f64 {
    10.0
}

const fn default_max_duplicates() -> usize {
    5
}

const fn default_zombie_timeout() -> u64 {
    300
}

const fn default_temp_cpu() -> f32 {
    85.0
}

const fn default_temp_gpu() -> f32 {
    80.0
}

const fn default_true() -> bool {
    true
}

fn default_provider() -> String {
    "claude-cli".into()
}

fn default_model() -> String {
    "claude-sonnet-4-20250514".into()
}

const fn default_cooldown() -> u64 {
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

// NOTE: Stored as raw string with tilde — expand with shellexpand at point of use.
fn default_database_path() -> String {
    "~/.local/share/vigil/vigil.db".into()
}

// --- Default impls ---

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
            cooldown_secs: default_cooldown(),
            ollama_url: None,
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

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_database_path(),
        }
    }
}

// --- AppConfig methods ---

impl AppConfig {
    /// Load config from default path or create default config file
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined,
    /// the file cannot be read, or the TOML content is invalid.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        Self::load_or_create(&path)
    }

    /// Load from a specific path, or create a default config file if missing
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the TOML content is invalid,
    /// or the default config file cannot be written.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load_from(path)
        } else {
            let config = Self::default();
            config.save_to(path)?;
            Ok(config)
        }
    }

    /// Load from a specific path
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the TOML content is invalid.
    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).context("Failed to read config file")?;
        toml::from_str(&content).context("Failed to parse config file")
    }

    /// Save config to default path
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be created,
    /// serialization fails, or the file cannot be written.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        self.save_to(&path)
    }

    /// Save config to a specific path, creating parent directories if needed
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created,
    /// serialization fails, or the file cannot be written.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).context("Failed to create config directory")?;
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(path, content).context("Failed to write config file")?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().context("Could not determine config directory")?;
        Ok(config_dir.join("vigil").join("config.toml"))
    }
}

impl From<&ThresholdConfig> for ThresholdSet {
    fn from(config: &ThresholdConfig) -> Self {
        let defaults = Self::default();

        // Clamp percentages to valid range
        let ram_warning = config.ram_warn_percent.clamp(0.0, 100.0);
        let ram_critical = config.ram_critical_percent.clamp(0.0, 100.0);
        let swap_warning = config.swap_warn_percent.clamp(0.0, 100.0);
        let disk_free = config.disk_min_free_percent.clamp(0.1, 100.0);
        let disk_warning = 100.0 - disk_free;

        // Ensure disk_warning < disk_critical (minimum 1% gap)
        let disk_critical = if disk_warning >= defaults.disk_critical {
            (disk_warning + 1.0).min(100.0)
        } else {
            defaults.disk_critical
        };

        Self {
            ram_warning,
            ram_critical: ram_critical.max(ram_warning),
            swap_warning,
            swap_critical: defaults.swap_critical.max(swap_warning),
            cpu_warning: defaults.cpu_warning,
            cpu_critical: defaults.cpu_critical,
            disk_warning,
            disk_critical,
            cpu_load_factor: config.cpu_load_factor.max(0.1),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_has_sensible_values() {
        let config = AppConfig::default();
        assert_eq!(config.general.mode, OperationMode::Suggest);
        assert_eq!(config.general.interval_secs, 5);
        assert_eq!(config.general.language, "fr");
        assert!((config.thresholds.ram_warn_percent - 80.0).abs() < f64::EPSILON);
        assert!((config.thresholds.ram_critical_percent - 90.0).abs() < f64::EPSILON);
        assert!((config.thresholds.swap_warn_percent - 40.0).abs() < f64::EPSILON);
        assert!((config.thresholds.cpu_load_factor - 2.0).abs() < f64::EPSILON);
        assert!((config.thresholds.disk_min_free_percent - 10.0).abs() < f64::EPSILON);
        assert_eq!(config.thresholds.max_duplicate_processes, 5);
        assert_eq!(config.thresholds.zombie_timeout_secs, 300);
        assert_eq!(config.ai.provider, "claude-cli");
        assert!(config.ai.enabled);
        assert!(config.ai.ollama_url.is_none());
        assert_eq!(config.ai.cooldown_secs, 60);
        assert!(config.notifications.desktop);
        assert!(config.notifications.terminal);
        assert!(config.notifications.log_file.is_none());
        assert!(config.notifications.webhook_url.is_none());
        assert_eq!(config.allowlist.ignore_commands.len(), 4);
        assert_eq!(config.allowlist.protected_commands.len(), 4);
        assert_eq!(config.database.path, "~/.local/share/vigil/vigil.db");
    }

    #[test]
    fn serde_roundtrip() {
        let config = AppConfig::default();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let deserialized: AppConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(deserialized.general.mode, config.general.mode);
        assert_eq!(
            deserialized.general.interval_secs,
            config.general.interval_secs
        );
        assert_eq!(deserialized.general.language, config.general.language);
        assert_eq!(deserialized.ai.provider, config.ai.provider);
        assert_eq!(deserialized.ai.model, config.ai.model);
        assert_eq!(deserialized.ai.cooldown_secs, config.ai.cooldown_secs);
        assert_eq!(deserialized.database.path, config.database.path);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let config: AppConfig = toml::from_str("").expect("parse empty toml");
        assert_eq!(config.general.mode, OperationMode::Suggest);
        assert_eq!(config.general.interval_secs, 5);
        assert_eq!(config.ai.provider, "claude-cli");
    }

    #[test]
    fn partial_toml_fills_missing_with_defaults() {
        let toml_str = r#"
[general]
interval_secs = 10

[ai]
provider = "ollama"
model = "llama3.2"
ollama_url = "http://localhost:11434"
"#;
        let config: AppConfig = toml::from_str(toml_str).expect("parse partial toml");
        assert_eq!(config.general.interval_secs, 10);
        assert_eq!(config.general.mode, OperationMode::Suggest);
        assert_eq!(config.general.language, "fr");
        assert_eq!(config.ai.provider, "ollama");
        assert_eq!(config.ai.model, "llama3.2");
        assert_eq!(
            config.ai.ollama_url.as_deref(),
            Some("http://localhost:11434")
        );
        assert!((config.thresholds.ram_warn_percent - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn load_from_file() {
        let toml_str = r#"
[general]
mode = "auto"
interval_secs = 2

[ai]
enabled = false
provider = "noop"
"#;
        let mut tmpfile = tempfile::NamedTempFile::new().expect("create tempfile");
        tmpfile
            .write_all(toml_str.as_bytes())
            .expect("write tmpfile");

        let config = AppConfig::load_from(tmpfile.path()).expect("load from file");
        assert_eq!(config.general.mode, OperationMode::Auto);
        assert_eq!(config.general.interval_secs, 2);
        assert!(!config.ai.enabled);
        assert_eq!(config.ai.provider, "noop");
    }

    #[test]
    fn config_path_contains_vigil() {
        let path = AppConfig::config_path().expect("config path");
        assert!(path.to_string_lossy().contains("vigil"));
        assert!(path.to_string_lossy().ends_with("config.toml"));
    }

    #[test]
    fn save_to_creates_file_and_directories() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("subdir").join("config.toml");

        let config = AppConfig::default();
        config.save_to(&path).expect("save_to");

        assert!(path.exists());
        let reloaded = AppConfig::load_from(&path).expect("reload");
        assert_eq!(reloaded.general.mode, config.general.mode);
        assert_eq!(reloaded.ai.provider, config.ai.provider);
        assert_eq!(reloaded.database.path, config.database.path);
    }

    #[test]
    fn load_or_create_loads_existing_file() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("config.toml");

        let toml_str = r#"
[general]
mode = "auto"
interval_secs = 42
"#;
        std::fs::write(&path, toml_str).expect("write");

        let config = AppConfig::load_or_create(&path).expect("load_or_create");
        assert_eq!(config.general.mode, OperationMode::Auto);
        assert_eq!(config.general.interval_secs, 42);
    }

    #[test]
    fn load_or_create_creates_default_when_missing() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("vigil").join("config.toml");

        assert!(!path.exists());
        let config = AppConfig::load_or_create(&path).expect("load_or_create");

        assert!(path.exists());
        assert_eq!(config.general.mode, OperationMode::Suggest);
        assert_eq!(config.ai.provider, "claude-cli");

        let reloaded = AppConfig::load_from(&path).expect("reload created file");
        assert_eq!(reloaded.general.mode, OperationMode::Suggest);
    }

    #[test]
    #[allow(unsafe_code)]
    fn load_and_save_use_default_config_path() {
        let dir = tempfile::tempdir().expect("create tempdir");

        // SAFETY: single-threaded test; we clean up after.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };

        // load() should create default when file is missing
        let config = AppConfig::load().expect("load default");
        assert_eq!(config.general.mode, OperationMode::Suggest);
        assert_eq!(config.ai.provider, "claude-cli");

        // File should now exist at the default path
        let expected_path = dir.path().join("vigil").join("config.toml");
        assert!(expected_path.exists());

        // save() should overwrite the file
        config.save().expect("save");
        let reloaded = AppConfig::load().expect("reload");
        assert_eq!(reloaded.general.mode, config.general.mode);

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn threshold_config_clamps_out_of_range_values() {
        let config = ThresholdConfig {
            ram_warn_percent: 150.0,
            ram_critical_percent: -10.0,
            disk_min_free_percent: -5.0,
            cpu_load_factor: -1.0,
            ..ThresholdConfig::default()
        };
        let thresholds = ThresholdSet::from(&config);
        // ram_warning clamped to 100.0, ram_critical clamped to 0.0 then raised to >= ram_warning
        assert!(thresholds.ram_warning <= 100.0);
        assert!(thresholds.ram_critical >= thresholds.ram_warning);
        // disk_free clamped to 0.1, so disk_warning = 99.9
        assert!(thresholds.disk_warning <= 99.9);
        assert!(thresholds.disk_critical > thresholds.disk_warning);
        // cpu_load_factor clamped to min 0.1
        assert!(thresholds.cpu_load_factor >= 0.1);
    }

    #[test]
    fn threshold_config_disk_inversion_prevented() {
        // disk_min_free_percent = 3.0 → disk_warning = 97.0 > default disk_critical (95.0)
        let config = ThresholdConfig {
            disk_min_free_percent: 3.0,
            ..ThresholdConfig::default()
        };
        let thresholds = ThresholdSet::from(&config);
        assert!(
            thresholds.disk_warning < thresholds.disk_critical,
            "disk_warning ({}) must be < disk_critical ({})",
            thresholds.disk_warning,
            thresholds.disk_critical
        );
    }

    #[test]
    fn load_from_nonexistent_file_fails() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let missing = dir.path().join("missing-config.toml");
        let result = AppConfig::load_from(&missing);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_toml_fails() {
        let mut tmpfile = tempfile::NamedTempFile::new().expect("create tempfile");
        tmpfile
            .write_all(b"this is not valid toml [[[")
            .expect("write");

        let result = AppConfig::load_from(tmpfile.path());
        assert!(result.is_err());
    }

    #[test]
    fn threshold_config_to_threshold_set_default_mapping() {
        let config = ThresholdConfig::default();
        let thresholds = ThresholdSet::from(&config);
        assert!((thresholds.ram_warning - 80.0).abs() < f64::EPSILON);
        assert!((thresholds.ram_critical - 90.0).abs() < f64::EPSILON);
        assert!((thresholds.swap_warning - 40.0).abs() < f64::EPSILON);
        assert!((thresholds.cpu_load_factor - 2.0).abs() < f64::EPSILON);
        assert!((thresholds.disk_warning - 90.0).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_config_to_threshold_set_custom_values() {
        let config = ThresholdConfig {
            ram_warn_percent: 70.0,
            ram_critical_percent: 85.0,
            swap_warn_percent: 30.0,
            cpu_load_factor: 3.0,
            disk_min_free_percent: 20.0,
            ..ThresholdConfig::default()
        };
        let thresholds = ThresholdSet::from(&config);
        assert!((thresholds.ram_warning - 70.0).abs() < f64::EPSILON);
        assert!((thresholds.ram_critical - 85.0).abs() < f64::EPSILON);
        assert!((thresholds.swap_warning - 30.0).abs() < f64::EPSILON);
        assert!((thresholds.cpu_load_factor - 3.0).abs() < f64::EPSILON);
        assert!((thresholds.disk_warning - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_config_preserves_unmapped_defaults() {
        let config = ThresholdConfig::default();
        let thresholds = ThresholdSet::from(&config);
        let defaults = ThresholdSet::default();
        assert!((thresholds.swap_critical - defaults.swap_critical).abs() < f64::EPSILON);
        assert!((thresholds.cpu_warning - defaults.cpu_warning).abs() < f64::EPSILON);
        assert!((thresholds.cpu_critical - defaults.cpu_critical).abs() < f64::EPSILON);
        assert!((thresholds.disk_critical - defaults.disk_critical).abs() < f64::EPSILON);
    }
}

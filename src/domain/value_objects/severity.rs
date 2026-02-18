use serde::{Deserialize, Serialize};

/// Severity level for alerts and diagnostics
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    #[must_use]
    pub const fn emoji(&self) -> &str {
        match self {
            Self::Low => "ℹ️",
            Self::Medium => "⚠️",
            Self::High => "🔶",
            Self::Critical => "🔴",
        }
    }

    #[must_use]
    pub const fn color(&self) -> &str {
        match self {
            Self::Low => "blue",
            Self::Medium => "yellow",
            Self::High => "red",
            Self::Critical => "bright red",
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_formats() {
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn emoji_returns_non_empty() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(!severity.emoji().is_empty());
        }
    }

    #[test]
    fn color_returns_non_empty() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(!severity.color().is_empty());
        }
    }

    #[test]
    fn serde_roundtrip() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let json = serde_json::to_string(&severity).expect("serialize");
            let deserialized: Severity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(severity, deserialized);
        }
    }
}

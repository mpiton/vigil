use serde::{Deserialize, Serialize};

/// Operating mode that determines how vigil handles detected issues
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OperationMode {
    /// Only observe and log — no actions taken
    #[default]
    Observe,
    /// Suggest actions but require human confirmation
    Suggest,
    /// Automatically execute safe actions
    Auto,
}

impl std::fmt::Display for OperationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Suggest => write!(f, "suggest"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_formats() {
        assert_eq!(OperationMode::Observe.to_string(), "observe");
        assert_eq!(OperationMode::Suggest.to_string(), "suggest");
        assert_eq!(OperationMode::Auto.to_string(), "auto");
    }

    #[test]
    fn default_is_observe() {
        assert_eq!(OperationMode::default(), OperationMode::Observe);
    }

    #[test]
    fn serde_roundtrip() {
        for mode in [
            OperationMode::Observe,
            OperationMode::Suggest,
            OperationMode::Auto,
        ] {
            let json = serde_json::to_string(&mode).expect("serialize");
            let deserialized: OperationMode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(mode, deserialized);
        }
    }
}

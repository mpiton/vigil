use serde::{Deserialize, Serialize};

/// Risk level associated with a suggested action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn display_formats() {
        assert_eq!(ActionRisk::Safe.to_string(), "safe");
        assert_eq!(ActionRisk::Moderate.to_string(), "moderate");
        assert_eq!(ActionRisk::Dangerous.to_string(), "dangerous");
    }

    #[test]
    fn serde_roundtrip() {
        for risk in [
            ActionRisk::Safe,
            ActionRisk::Moderate,
            ActionRisk::Dangerous,
        ] {
            let json = serde_json::to_string(&risk).expect("serialize");
            let deserialized: ActionRisk = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(risk, deserialized);
        }
    }
}

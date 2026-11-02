//! Risk classification.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Risk level of an operation as assessed by the controller. Ordered: `Low < Medium < High <
/// Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Routine.
    Low,
    /// Worth a look.
    Medium,
    /// Requires a typed confirmation from the developer.
    High,
    /// Requires a typed confirmation and is never reusable.
    Critical,
}

impl RiskLevel {
    /// Whether the approval prompt for this risk level must require the developer to type a
    /// confirmation string rather than press a key.
    #[must_use]
    pub const fn requires_typed_confirmation(self) -> bool {
        matches!(self, RiskLevel::High | RiskLevel::Critical)
    }

    /// Lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_and_confirmation() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
        assert!(!RiskLevel::Low.requires_typed_confirmation());
        assert!(!RiskLevel::Medium.requires_typed_confirmation());
        assert!(RiskLevel::High.requires_typed_confirmation());
        assert!(RiskLevel::Critical.requires_typed_confirmation());
        assert_eq!(serde_json::to_string(&RiskLevel::High).unwrap(), "\"high\"");
    }
}

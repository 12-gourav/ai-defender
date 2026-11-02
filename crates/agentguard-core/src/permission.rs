//! Permission levels (the four security modes).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::SecurityError;

/// The security mode a session runs in. The mode is chosen by the developer through the
/// trusted interface; an agent can never change it.
///
/// This type carries no authorisation logic. What each mode permits is decided by the
/// permission engine (a later phase) against the effective policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionLevel {
    /// Read authorised files, inspect Git, analyse. No modifications.
    ReadOnly,
    /// Modify authorised source files, build and test inside the sandbox.
    Development,
    /// Additionally request approval-gated commits, feature-branch pushes, dependency
    /// operations and explicitly approved sensitive operations.
    DeveloperAuthorized,
    /// Narrowed file set and commands; every sensitive action requires approval.
    Restricted,
}

impl PermissionLevel {
    /// All levels, in ascending order of capability for display purposes.
    pub const ALL: [PermissionLevel; 4] = [
        PermissionLevel::ReadOnly,
        PermissionLevel::Development,
        PermissionLevel::DeveloperAuthorized,
        PermissionLevel::Restricted,
    ];

    /// The canonical name as written in `.agent-security.yml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PermissionLevel::ReadOnly => "READ_ONLY",
            PermissionLevel::Development => "DEVELOPMENT",
            PermissionLevel::DeveloperAuthorized => "DEVELOPER_AUTHORIZED",
            PermissionLevel::Restricted => "RESTRICTED",
        }
    }

    /// One-line description for help output.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            PermissionLevel::ReadOnly => "read and analyse only; no modifications",
            PermissionLevel::Development => "edit, build and test inside the sandbox",
            PermissionLevel::DeveloperAuthorized => {
                "development plus approval-gated commits, pushes and dependency changes"
            }
            PermissionLevel::Restricted => "narrowed access; every sensitive action needs approval",
        }
    }
}

impl fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PermissionLevel {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|l| l.as_str() == s)
            .ok_or(SecurityError::UnknownVariant {
                kind: "permission level",
                expected: "READ_ONLY, DEVELOPMENT, DEVELOPER_AUTHORIZED, RESTRICTED",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_exactly() {
        for level in PermissionLevel::ALL {
            assert_eq!(level.as_str().parse::<PermissionLevel>().unwrap(), level);
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, format!("\"{}\"", level.as_str()));
        }
    }

    #[test]
    fn parsing_is_case_sensitive() {
        assert!("development".parse::<PermissionLevel>().is_err());
        assert!("Development".parse::<PermissionLevel>().is_err());
        let bad: Result<PermissionLevel, _> = serde_json::from_str("\"development\"");
        assert!(bad.is_err());
    }
}

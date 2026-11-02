//! Process-environment helpers that never expose values.

/// Names of the environment variables present in this process, sorted. Values are never
/// returned by this crate; a caller that needs one reads it explicitly and treats it as a
/// potential secret.
#[must_use]
pub fn variable_names() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Whether an environment variable name should be treated as sensitive. Delegates to the
/// shared redaction rules so logging and audit agree.
#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    agentguard_core::redact::is_sensitive_field(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_only() {
        let names = variable_names();
        assert!(names.iter().any(|n| n == "PATH") || names.is_empty());
        for n in &names {
            assert!(!n.contains('='));
        }
    }

    #[test]
    fn sensitivity_agrees_with_core() {
        assert!(is_sensitive_name("GITHUB_TOKEN"));
        assert!(is_sensitive_name("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_sensitive_name("HOME"));
    }
}

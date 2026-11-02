//! Structured logging with redaction at the write boundary.
//!
//! Events are rendered by a single layer that owns the output stream. Every field value passes
//! through [`agentguard_core::redact::redact_field`] before it is written, so a secret that
//! reaches a `tracing` macro by mistake is replaced with `[REDACTED]` rather than persisted.
//! The layer is deliberately independent of `tracing_subscriber::fmt` so the redaction cannot
//! be bypassed by a formatter swap.
//!
//! The same layer shape (an [`EventSink`] receiving fully redacted lines) is what the audit
//! engine will subscribe to in a later phase.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Arc, Mutex};

use agentguard_core::redact::redact_field;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

/// Environment variable that overrides the verbosity flag with an `EnvFilter` directive.
pub const LOG_ENV_VAR: &str = "AGENTGUARD_LOG";

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable single line per event.
    #[default]
    Pretty,
    /// One JSON object per line.
    Json,
}

/// Errors from initialising logging.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoggingError {
    /// A global subscriber was already installed.
    #[error("logging was already initialised")]
    AlreadyInitialised,
    /// The `AGENTGUARD_LOG` directive could not be parsed.
    #[error("invalid {LOG_ENV_VAR} filter directive")]
    InvalidFilter,
}

/// Where rendered lines go. Implemented for stderr and for in-memory buffers in tests.
pub trait EventSink: Send + Sync + 'static {
    /// Write one complete line (without trailing newline).
    fn write_line(&self, line: &str);
}

/// Sink writing to the process's standard error stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrSink;

impl EventSink for StderrSink {
    fn write_line(&self, line: &str) {
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        // A failed write to stderr has nowhere to be reported; it is ignored on purpose.
        let _ = writeln!(handle, "{line}");
    }
}

/// Sink collecting lines in memory. Used by tests and available to the audit engine.
#[derive(Debug, Default, Clone)]
pub struct MemorySink {
    lines: Arc<Mutex<Vec<String>>>,
}

impl MemorySink {
    /// Create an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the collected lines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

impl EventSink for MemorySink {
    fn write_line(&self, line: &str) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.push(line.to_owned());
        }
    }
}

/// A rendered, redacted event.
#[derive(Debug, Serialize)]
struct Rendered<'a> {
    timestamp: String,
    level: &'a str,
    target: &'a str,
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<(String, String)>,
}

/// Collects event fields, redacting as it goes.
#[derive(Default)]
struct RedactingVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl RedactingVisitor {
    fn push(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = redact_field("message", value);
        } else {
            self.fields
                .push((field.name().to_owned(), redact_field(field.name(), value)));
        }
    }
}

impl Visit for RedactingVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field, &format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, &value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, &value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, &value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.push(field, &value.to_string());
    }
}

/// The layer that renders and writes events.
pub struct RedactingLayer<K: EventSink> {
    format: LogFormat,
    sink: K,
}

impl<K: EventSink> RedactingLayer<K> {
    /// Create a layer writing to `sink`.
    pub fn new(format: LogFormat, sink: K) -> Self {
        Self { format, sink }
    }

    fn render(&self, event: &Event<'_>) -> String {
        let mut visitor = RedactingVisitor::default();
        event.record(&mut visitor);
        let meta = event.metadata();
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_owned());
        let rendered = Rendered {
            timestamp,
            level: level_name(*meta.level()),
            target: meta.target(),
            message: visitor.message,
            fields: visitor.fields,
        };
        match self.format {
            LogFormat::Json => serde_json::to_string(&rendered).unwrap_or_else(|_| {
                "{\"level\":\"ERROR\",\"message\":\"unrenderable event\"}".into()
            }),
            LogFormat::Pretty => {
                let mut line = format!(
                    "{} {:>5} {}: {}",
                    rendered.timestamp, rendered.level, rendered.target, rendered.message
                );
                for (k, v) in &rendered.fields {
                    // Values are already redacted; quote them so field boundaries stay clear.
                    let _ = write!(line, " {k}={v:?}");
                }
                line
            }
        }
    }
}

impl<S, K> Layer<S> for RedactingLayer<K>
where
    S: Subscriber,
    K: EventSink,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let line = self.render(event);
        self.sink.write_line(&line);
    }
}

const fn level_name(level: Level) -> &'static str {
    match level {
        Level::TRACE => "TRACE",
        Level::DEBUG => "DEBUG",
        Level::INFO => "INFO",
        Level::WARN => "WARN",
        Level::ERROR => "ERROR",
    }
}

/// Options for [`init`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LogOptions {
    /// Number of `-v` flags: 0 = warn, 1 = info, 2 = debug, 3+ = trace.
    pub verbosity: u8,
    /// Output format.
    pub format: LogFormat,
}

impl LogOptions {
    /// The default filter directive implied by `verbosity`.
    #[must_use]
    pub const fn default_directive(&self) -> &'static str {
        match self.verbosity {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    }
}

/// Build the filter from `AGENTGUARD_LOG` if set, else from the verbosity flag.
fn build_filter(options: LogOptions) -> Result<EnvFilter, LoggingError> {
    match std::env::var(LOG_ENV_VAR) {
        Ok(directive) if !directive.trim().is_empty() => {
            EnvFilter::try_new(directive).map_err(|_| LoggingError::InvalidFilter)
        }
        _ => {
            EnvFilter::try_new(options.default_directive()).map_err(|_| LoggingError::InvalidFilter)
        }
    }
}

/// Install the global subscriber writing to standard error.
pub fn init(options: LogOptions) -> Result<(), LoggingError> {
    init_with_sink(options, StderrSink)
}

/// Install the global subscriber writing to `sink`.
pub fn init_with_sink<K: EventSink>(options: LogOptions, sink: K) -> Result<(), LoggingError> {
    let filter = build_filter(options)?;
    tracing_subscriber::registry()
        .with(filter)
        .with(RedactingLayer::new(options.format, sink))
        .try_init()
        .map_err(|_| LoggingError::AlreadyInitialised)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber::with_default;

    fn capture(format: LogFormat, f: impl FnOnce()) -> Vec<String> {
        let sink = MemorySink::new();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("trace"))
            .with(RedactingLayer::new(format, sink.clone()));
        with_default(subscriber, f);
        sink.lines()
    }

    #[test]
    fn redacts_sensitive_field_names_and_secret_shapes() {
        let lines = capture(LogFormat::Pretty, || {
            tracing::info!(password = "hunter2", branch = "main", "pushing");
            tracing::warn!(
                note = "token ghp_0123456789abcdefghijklmnopqrstuvwxyz used",
                "x"
            );
        });
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("password=\"[REDACTED]\""));
        assert!(lines[0].contains("branch=\"main\""));
        assert!(!lines[0].contains("hunter2"));
        assert!(lines[1].contains("[REDACTED]"));
        assert!(!lines[1].contains("ghp_"));
    }

    #[test]
    fn json_output_is_parseable_and_redacted() {
        let lines = capture(LogFormat::Json, || {
            tracing::error!(api_key = "AKIAIOSFODNN7EXAMPLE", "failed");
        });
        let value: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(value["level"], "ERROR");
        assert_eq!(value["message"], "failed");
        assert_eq!(value["fields"][0][0], "api_key");
        assert_eq!(value["fields"][0][1], "[REDACTED]");
        assert!(value["timestamp"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn message_itself_is_redacted() {
        let lines = capture(LogFormat::Pretty, || {
            tracing::info!("credential AKIAIOSFODNN7EXAMPLE leaked");
        });
        assert!(lines[0].contains("credential [REDACTED] leaked"));
    }

    #[test]
    fn verbosity_maps_to_directives() {
        assert_eq!(
            LogOptions {
                verbosity: 0,
                ..Default::default()
            }
            .default_directive(),
            "warn"
        );
        assert_eq!(
            LogOptions {
                verbosity: 1,
                ..Default::default()
            }
            .default_directive(),
            "info"
        );
        assert_eq!(
            LogOptions {
                verbosity: 2,
                ..Default::default()
            }
            .default_directive(),
            "debug"
        );
        assert_eq!(
            LogOptions {
                verbosity: 9,
                ..Default::default()
            }
            .default_directive(),
            "trace"
        );
    }
}

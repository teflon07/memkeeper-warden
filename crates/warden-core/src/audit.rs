//! Append-only JSONL audit log. The source of truth for what the broker decided.
//! Separate from memkeeper on purpose: audit integrity must not be mutable the way
//! memory is. (Optional tamper-evident hash-chaining is deferred follow-on work.)

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// One audit record. Borrowed fields so the broker can render without owning.
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry<'a> {
    /// Timestamp tag, supplied by the caller (v1 serve layer emits `epoch:<secs>`).
    pub ts: &'a str,
    /// Skill that made the request.
    pub skill: &'a str,
    /// Capability class token (e.g. `fs:read`).
    pub capability: &'a str,
    /// Granted scope that matched, or empty if none.
    pub scope: &'a str,
    /// Concrete target of the request.
    pub target: &'a str,
    /// `allow` or `deny`.
    pub decision: &'a str,
    /// Short human reason.
    pub reason: &'a str,
}

impl AuditEntry<'_> {
    /// Render as a single JSON object line (no trailing newline).
    #[must_use]
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"ts\":\"{}\",\"skill\":\"{}\",\"capability\":\"{}\",\"scope\":\"{}\",\"target\":\"{}\",\"decision\":\"{}\",\"reason\":\"{}\"}}",
            esc(self.ts), esc(self.skill), esc(self.capability), esc(self.scope),
            esc(self.target), esc(self.decision), esc(self.reason),
        )
    }
}

/// Minimal JSON string escaping for the fields warden writes.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

/// Append one entry as a line to the audit log, creating the file if needed.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the file cannot be opened or written.
pub fn append(path: &Path, entry: &AuditEntry<'_>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", entry.to_json_line())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_json_line() {
        let entry = AuditEntry {
            ts: "2026-06-11T09:00:00Z",
            skill: "morning-note",
            capability: "fs:read",
            scope: "/a",
            target: "/a/b.csv",
            decision: "allow",
            reason: "policy grant",
        };
        let line = entry.to_json_line();
        assert!(line.starts_with('{') && line.ends_with('}'));
        assert!(line.contains("\"skill\":\"morning-note\""));
        assert!(line.contains("\"decision\":\"allow\""));
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        let entry = AuditEntry {
            ts: "t",
            skill: "s",
            capability: "exec",
            scope: "sh",
            target: "say \"hi\"\\done",
            decision: "deny",
            reason: "no grant",
        };
        let line = entry.to_json_line();
        assert!(line.contains(r#"say \"hi\"\\done"#));
    }

    #[test]
    fn appends_to_file() {
        let dir = std::env::temp_dir().join("warden_audit_test_unique_7");
        let _ = std::fs::remove_file(&dir);
        let entry = AuditEntry {
            ts: "t",
            skill: "s",
            capability: "fs:read",
            scope: "/a",
            target: "/a/b",
            decision: "allow",
            reason: "ok",
        };
        append(&dir, &entry).unwrap();
        append(&dir, &entry).unwrap();
        let contents = std::fs::read_to_string(&dir).unwrap();
        assert_eq!(contents.lines().count(), 2);
        let _ = std::fs::remove_file(&dir);
    }
}

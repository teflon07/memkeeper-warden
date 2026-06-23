//! Hand-rolled request/response envelope for the warden serve loop. Minimal
//! string-field extraction (mirrors memkeeper's dep-light JSON handling). Inputs
//! are simple flat objects of string fields produced by the MCP adapter.

/// A parsed broker request.
pub struct WireRequest {
    /// The skill identifier.
    pub skill: String,
    /// The capability token (e.g. `fs:read`).
    pub capability: String,
    /// The resource target.
    pub target: String,
    /// When true, return the decision only — never forward (read/write) the action.
    pub decide_only: bool,
}

/// Extract a `"key":"value"` string field from a flat JSON object.
///
/// Matches the occurrence of `"key"` that is a KEY — i.e. followed (after
/// optional whitespace) by a colon — so a value that happens to equal the key
/// name (e.g. `"event":"decision"` vs the `"decision"` key) does not shadow it.
/// Non-string values yield `None`.
pub(crate) fn field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    loop {
        let idx = line[from..].find(&needle)? + from;
        let after_key = line[idx + needle.len()..].trim_start();
        let Some(rest) = after_key.strip_prefix(':') else {
            // This occurrence was a value, not a key; keep looking.
            from = idx + needle.len();
            continue;
        };
        let after = rest.trim_start().strip_prefix('"')?;
        // Read until the next unescaped quote.
        let mut out = String::new();
        let mut chars = after.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(match n {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                    }
                }
                '"' => return Some(out),
                other => out.push(other),
            }
        }
        return None;
    }
}

/// Extract a `"key":true` boolean field from a flat JSON object. Absent or any
/// non-`true` value reads as false.
fn bool_field(line: &str, key: &str) -> bool {
    let needle = format!("\"{key}\"");
    let Some(start) = line.find(&needle) else {
        return false;
    };
    let rest = &line[start + needle.len()..];
    let Some(colon) = rest.find(':') else {
        return false;
    };
    rest[colon + 1..].trim_start().starts_with("true")
}

/// Parse one request line into a [`WireRequest`].
///
/// # Errors
/// Returns a message if any required field is absent.
pub fn parse_request_line(line: &str) -> Result<WireRequest, String> {
    let skill = field(line, "skill").ok_or("missing skill")?;
    let capability = field(line, "capability").ok_or("missing capability")?;
    let target = field(line, "target").ok_or("missing target")?;
    Ok(WireRequest {
        skill,
        capability,
        target,
        decide_only: bool_field(line, "decide_only"),
    })
}

/// Render a response line. `data` carries `fs:read` contents when present.
#[must_use]
pub fn response_line(decision: &str, reason: &str, data: Option<&str>) -> String {
    match data {
        Some(d) => format!(
            "{{\"decision\":\"{}\",\"reason\":\"{}\",\"data\":\"{}\"}}",
            esc(decision),
            esc(reason),
            esc(d)
        ),
        None => format!(
            "{{\"decision\":\"{}\",\"reason\":\"{}\"}}",
            esc(decision),
            esc(reason)
        ),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_request_line() {
        let req =
            parse_request_line(r#"{"skill":"s","capability":"fs:read","target":"/a/b"}"#).unwrap();
        assert_eq!(req.skill, "s");
        assert_eq!(req.capability, "fs:read");
        assert_eq!(req.target, "/a/b");
    }

    #[test]
    fn rejects_missing_fields() {
        assert!(parse_request_line(r#"{"skill":"s"}"#).is_err());
    }

    #[test]
    fn parses_decide_only_true() {
        let req = parse_request_line(
            r#"{"skill":"s","capability":"fs:read","target":"/a/b","decide_only":true}"#,
        )
        .unwrap();
        assert!(req.decide_only);
    }

    #[test]
    fn decide_only_defaults_false() {
        let req =
            parse_request_line(r#"{"skill":"s","capability":"fs:read","target":"/a/b"}"#).unwrap();
        assert!(!req.decide_only);
    }

    #[test]
    fn renders_response() {
        let line = response_line("deny", "no grant", None);
        assert!(line.contains("\"decision\":\"deny\""));
        assert!(line.contains("\"reason\":\"no grant\""));
    }
}

//! User-owned grant policy. The manifest *requests* capabilities; this file
//! *grants* them. Deny-by-default: a request with no matching grant resolves to
//! `None` (undecided) and the broker denies unless an interactive prompt grants.

use std::fmt::Write as _;

use crate::capability::{Capability, CapabilityClass};
use crate::request::Request;
use crate::scope;

/// An allow or deny decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Permit the action.
    Allow,
    /// Refuse the action.
    Deny,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// One recorded grant: which skill, which capability, allow or deny.
#[derive(Debug, Clone)]
struct Grant {
    skill: String,
    capability: Capability,
    decision: Decision,
}

/// The set of recorded grants.
#[derive(Debug, Default)]
pub struct Policy {
    grants: Vec<Grant>,
}

impl Policy {
    /// Resolve a request for a skill. `None` means undecided (deny-by-default).
    /// A matching `Deny` takes precedence over a matching `Allow`.
    #[must_use]
    pub fn resolve(&self, skill: &str, request: &Request) -> Option<Decision> {
        let mut decision = None;
        for g in &self.grants {
            if g.skill == skill && scope::matches(&g.capability, request) {
                match g.decision {
                    Decision::Deny => return Some(Decision::Deny),
                    Decision::Allow => decision = Some(Decision::Allow),
                }
            }
        }
        decision
    }

    /// Record a grant decision.
    pub fn record(&mut self, skill: &str, capability: Capability, decision: Decision) {
        self.grants.push(Grant {
            skill: skill.to_string(),
            capability,
            decision,
        });
    }

    /// Serialize to the dependency-free line format.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for g in &self.grants {
            let _ = writeln!(
                out,
                "{}\t{}\t{}\t{}",
                g.skill,
                g.capability.class.as_str(),
                g.capability.scope,
                g.decision.as_str(),
            );
        }
        out
    }

    /// Parse from the line format. Blank lines and `#` comments are ignored.
    ///
    /// # Errors
    /// Returns a message string if a line is malformed.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut grants = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 4 {
                return Err(format!("policy line {}: expected 4 tab fields", i + 1));
            }
            let class = CapabilityClass::parse(parts[1])
                .ok_or_else(|| format!("policy line {}: unknown class {}", i + 1, parts[1]))?;
            let decision = match parts[3] {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny,
                other => return Err(format!("policy line {}: bad decision {other}", i + 1)),
            };
            grants.push(Grant {
                skill: parts[0].to_string(),
                capability: Capability {
                    class,
                    scope: parts[2].to_string(),
                },
                decision,
            });
        }
        Ok(Self { grants })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityClass;
    use crate::request::Request;

    #[test]
    fn undecided_when_no_grant() {
        let p = Policy::default();
        let r = Request::new(CapabilityClass::FsRead, "/a/b");
        assert_eq!(p.resolve("skill", &r), None);
    }

    #[test]
    fn allow_grant_matches_request_in_scope() {
        let mut p = Policy::default();
        p.record(
            "morning-note",
            Capability::parse("fs:read /a").unwrap(),
            Decision::Allow,
        );
        let r = Request::new(CapabilityClass::FsRead, "/a/b");
        assert_eq!(p.resolve("morning-note", &r), Some(Decision::Allow));
    }

    #[test]
    fn grant_is_scoped_to_skill() {
        let mut p = Policy::default();
        p.record(
            "morning-note",
            Capability::parse("fs:read /a").unwrap(),
            Decision::Allow,
        );
        let r = Request::new(CapabilityClass::FsRead, "/a/b");
        assert_eq!(p.resolve("other-skill", &r), None);
    }

    #[test]
    fn deny_grant_short_circuits() {
        let mut p = Policy::default();
        p.record("s", Capability::parse("exec rm").unwrap(), Decision::Deny);
        let r = Request::new(CapabilityClass::Exec, "rm");
        assert_eq!(p.resolve("s", &r), Some(Decision::Deny));
    }

    #[test]
    fn round_trips_through_text() {
        let mut p = Policy::default();
        p.record(
            "s",
            Capability::parse("net api.anthropic.com").unwrap(),
            Decision::Allow,
        );
        let text = p.to_text();
        let reloaded = Policy::from_text(&text).unwrap();
        let r = Request::new(CapabilityClass::Net, "api.anthropic.com");
        assert_eq!(reloaded.resolve("s", &r), Some(Decision::Allow));
    }
}

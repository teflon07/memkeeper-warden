//! The broker: resolve a request against policy, audit the decision, and perform
//! mediated `fs` actions when allowed. Non-interactive contexts never prompt —
//! an undecided request is denied (no silent 3am grants).
//!
//! Limitation (v1): the capability check is lexical (see `scope`). The fs
//! forwarder does NOT resolve symlinks, so a symlink inside a granted directory
//! can still point outside it. Symlink/realpath hardening is deliberate
//! follow-on work; v1 mediates and audits, it does not contain a hostile target.

use crate::audit::{self, AuditEntry};
use crate::capability::{Capability, CapabilityClass};
use crate::policy::{Decision, Policy};
use crate::request::Request;
use crate::scope;
use std::collections::HashMap;
use std::path::PathBuf;

/// The capability broker.
pub struct Broker {
    policy: Policy,
    audit_path: PathBuf,
    /// When true, undecided requests may be prompted (wired by the serve layer).
    /// When false (scheduled jobs), undecided always denies.
    interactive: bool,
    /// Per-skill declared capabilities (from SKILL.md). Empty for principals
    /// with no manifest (e.g. `claude-code-main`), which fall through to policy.
    manifests: HashMap<String, Vec<Capability>>,
}

impl Broker {
    /// Construct a broker over a policy and audit-log path.
    #[must_use]
    pub fn new(policy: Policy, audit_path: PathBuf, interactive: bool) -> Self {
        Self {
            policy,
            audit_path,
            interactive,
            manifests: HashMap::new(),
        }
    }

    /// Whether this broker may prompt for undecided requests.
    #[must_use]
    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Register a skill's declared capabilities. A skill with a registered
    /// manifest may only act within it; an unregistered skill is policy-only.
    pub fn register_manifest(&mut self, skill: &str, caps: Vec<Capability>) {
        self.manifests.insert(skill.to_string(), caps);
    }

    /// Decide a request, returning the decision AND its static reason string,
    /// writing one audit line. Deny-by-default.
    ///
    /// In v1 the interactive prompt is not yet wired, so an undecided request is
    /// denied in both modes; `interactive` is recorded for the serve layer to act
    /// on in a follow-on. This keeps the non-interactive guarantee exact today.
    pub fn decide_verbose(
        &mut self,
        skill: &str,
        request: &Request,
        ts: &str,
    ) -> (Decision, &'static str) {
        // Manifest gate: if this skill declared capabilities, the request must
        // be covered by at least one of them before policy is even consulted.
        let manifest_undeclared = self
            .manifests
            .get(skill)
            .is_some_and(|caps| !caps.iter().any(|c| scope::matches(c, request)));

        let (decision, scope, reason) = if manifest_undeclared {
            (Decision::Deny, String::new(), "manifest: undeclared")
        } else {
            match self.policy.resolve(skill, request) {
                Some(Decision::Allow) => (Decision::Allow, request.target.clone(), "policy grant"),
                Some(Decision::Deny) => (Decision::Deny, request.target.clone(), "policy deny"),
                None => (Decision::Deny, String::new(), "no grant (deny-by-default)"),
            }
        };
        let entry = AuditEntry {
            ts,
            skill,
            capability: request.class.as_str(),
            scope: &scope,
            target: &request.target,
            decision: match decision {
                Decision::Allow => "allow",
                Decision::Deny => "deny",
            },
            reason,
        };
        if let Err(e) = audit::append(&self.audit_path, &entry) {
            eprintln!("[warden] audit append failed: {e}");
        }
        (decision, reason)
    }

    /// Decide a request, writing one audit line. Deny-by-default.
    pub fn decide(&mut self, skill: &str, request: &Request, ts: &str) -> Decision {
        self.decide_verbose(skill, request, ts).0
    }

    /// Mediated `fs:read`: decide, then read the file only if allowed.
    ///
    /// # Errors
    /// Returns an error string on denial or read failure.
    pub fn fs_read(&mut self, skill: &str, request: &Request, ts: &str) -> Result<String, String> {
        if request.class != CapabilityClass::FsRead {
            return Err("capability_denied".to_string());
        }
        match self.decide(skill, request, ts) {
            Decision::Allow => {
                std::fs::read_to_string(&request.target).map_err(|e| format!("read failed: {e}"))
            }
            Decision::Deny => Err("capability_denied".to_string()),
        }
    }

    /// Mediated `fs:write`: decide, then write the file only if allowed.
    ///
    /// # Errors
    /// Returns an error string on denial or write failure.
    pub fn fs_write(
        &mut self,
        skill: &str,
        request: &Request,
        contents: &[u8],
        ts: &str,
    ) -> Result<(), String> {
        if request.class != CapabilityClass::FsWrite {
            return Err("capability_denied".to_string());
        }
        match self.decide(skill, request, ts) {
            Decision::Allow => {
                std::fs::write(&request.target, contents).map_err(|e| format!("write failed: {e}"))
            }
            Decision::Deny => Err("capability_denied".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilityClass};
    use crate::policy::{Decision, Policy};
    use crate::request::Request;

    fn broker_with(grant: Option<(&str, &str)>, audit: &std::path::Path) -> Broker {
        let mut policy = Policy::default();
        if let Some((skill, cap)) = grant {
            policy.record(skill, Capability::parse(cap).unwrap(), Decision::Allow);
        }
        // Non-interactive: undecided requests are denied, never prompted.
        Broker::new(policy, audit.to_path_buf(), false)
    }

    #[test]
    fn denies_undeclared_request() {
        let audit = std::env::temp_dir().join("warden_broker_deny_8.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_with(None, &audit);
        let req = Request::new(CapabilityClass::FsRead, "/etc/hosts");
        let d = b.decide("skill", &req, "2026-06-11T00:00:00Z");
        assert_eq!(d, Decision::Deny);
        let log = std::fs::read_to_string(&audit).unwrap();
        assert!(log.contains("\"decision\":\"deny\""));
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn allows_granted_request() {
        let audit = std::env::temp_dir().join("warden_broker_allow_8.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_with(Some(("s", "fs:read /a")), &audit);
        let req = Request::new(CapabilityClass::FsRead, "/a/b");
        assert_eq!(b.decide("s", &req, "t"), Decision::Allow);
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn non_interactive_undecided_is_deny() {
        let audit = std::env::temp_dir().join("warden_broker_ni_8.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_with(Some(("s", "fs:read /a")), &audit);
        let req = Request::new(CapabilityClass::FsRead, "/b/c");
        assert_eq!(b.decide("s", &req, "t"), Decision::Deny);
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn fs_read_forwarder_reads_only_when_allowed() {
        let dir = std::env::temp_dir().join("warden_fs_fwd_8");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("data.txt");
        std::fs::write(&file, b"hello").unwrap();
        let audit = dir.join("audit.jsonl");

        let mut policy = Policy::default();
        policy.record(
            "s",
            Capability::parse(&format!("fs:read {}", dir.display())).unwrap(),
            Decision::Allow,
        );
        let mut b = Broker::new(policy, audit.clone(), false);

        let req = Request::new(CapabilityClass::FsRead, file.to_str().unwrap());
        let got = b.fs_read("s", &req, "t").unwrap();
        assert_eq!(got, "hello");

        let outside = Request::new(CapabilityClass::FsRead, "/etc/hosts");
        assert!(b.fs_read("s", &outside, "t").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_read_rejects_non_fsread_class() {
        let dir = std::env::temp_dir().join("warden_fs_class_8");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("data.txt");
        std::fs::write(&file, b"secret").unwrap();
        let audit = dir.join("audit.jsonl");
        let mut policy = Policy::default();
        // Grant fs:write on the dir, NOT fs:read.
        policy.record(
            "s",
            Capability::parse(&format!("fs:write {}", dir.display())).unwrap(),
            Decision::Allow,
        );
        let mut b = Broker::new(policy, audit, false);
        // A FsWrite-class request must NOT be readable via fs_read.
        let req = Request::new(CapabilityClass::FsWrite, file.to_str().unwrap());
        assert!(b.fs_read("s", &req, "t").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn broker_with_manifest(
        manifest: &[&str],
        grant: Option<(&str, &str)>,
        audit: &std::path::Path,
    ) -> Broker {
        let mut policy = Policy::default();
        if let Some((skill, cap)) = grant {
            policy.record(skill, Capability::parse(cap).unwrap(), Decision::Allow);
        }
        let mut b = Broker::new(policy, audit.to_path_buf(), false);
        let caps = manifest
            .iter()
            .map(|c| Capability::parse(c).unwrap())
            .collect();
        b.register_manifest("s", caps);
        b
    }

    #[test]
    fn manifest_blocks_undeclared_even_when_policy_allows() {
        let audit = std::env::temp_dir().join("warden_man_undecl.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_with_manifest(&["fs:read /a"], Some(("s", "fs:read /b")), &audit);
        let req = Request::new(CapabilityClass::FsRead, "/b/c");
        assert_eq!(b.decide("s", &req, "t"), Decision::Deny);
        let log = std::fs::read_to_string(&audit).unwrap();
        assert!(log.contains("manifest: undeclared"));
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn manifest_declared_then_policy_allows() {
        let audit = std::env::temp_dir().join("warden_man_ok.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_with_manifest(&["fs:read /a"], Some(("s", "fs:read /a")), &audit);
        let req = Request::new(CapabilityClass::FsRead, "/a/x");
        assert_eq!(b.decide("s", &req, "t"), Decision::Allow);
        let log = std::fs::read_to_string(&audit).unwrap();
        assert!(log.contains("policy grant"));
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn manifest_declared_but_policy_undecided_denies() {
        let audit = std::env::temp_dir().join("warden_man_pol.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_with_manifest(&["fs:read /a"], None, &audit);
        let req = Request::new(CapabilityClass::FsRead, "/a/x");
        assert_eq!(b.decide("s", &req, "t"), Decision::Deny);
        let log = std::fs::read_to_string(&audit).unwrap();
        assert!(log.contains("no grant (deny-by-default)"));
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn no_manifest_falls_through_to_policy() {
        let audit = std::env::temp_dir().join("warden_man_none.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut policy = Policy::default();
        policy.record(
            "t",
            Capability::parse("fs:read /a").unwrap(),
            Decision::Allow,
        );
        let mut b = Broker::new(policy, audit.clone(), false);
        let req = Request::new(CapabilityClass::FsRead, "/a/x");
        assert_eq!(b.decide("t", &req, "ts"), Decision::Allow);
        let _ = std::fs::remove_file(&audit);
    }
}

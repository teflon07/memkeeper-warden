//! Scope matching: does a granted capability authorize a concrete request?
//!
//! Security-critical. `fs` normalizes both sides (resolving `.`/`..` lexically)
//! and requires a path-component prefix so traversal and sibling-prefix tricks
//! are denied. `net` matches on whole DNS labels so suffix spoofing is denied.
//!
//! Limitations (v1): matching is purely lexical — symlinks are NOT resolved, so
//! a symlink inside a granted directory can point outside it. A future fs
//! forwarder hardening must validate the resolved path; v1 does NOT, so a
//! passing match does not guarantee the resolved target is in-scope.
//! Wildcard net scopes do not understand public suffixes (`*.com` matches any
//! `.com` host) — that guard belongs in the manifest layer.

use crate::capability::{Capability, CapabilityClass};
use crate::request::Request;
use std::path::{Component, Path, PathBuf};

/// Return `true` if `granted` authorizes `request`.
#[must_use]
pub fn matches(granted: &Capability, request: &Request) -> bool {
    if granted.class != request.class {
        return false;
    }
    match granted.class {
        CapabilityClass::FsRead | CapabilityClass::FsWrite => {
            fs_matches(&granted.scope, &request.target)
        }
        CapabilityClass::Net => net_matches(&granted.scope, &request.target),
        CapabilityClass::Exec
        | CapabilityClass::MemoryRead
        | CapabilityClass::MemoryWrite
        | CapabilityClass::Secrets => granted.scope == request.target,
    }
}

/// Lexically normalize a path: drop `.`, resolve `..` against prior components.
/// Purely textual (no filesystem touch) so non-existent paths still normalize,
/// and `..` cannot escape a normalized prefix.
fn normalize(path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn fs_matches(scope: &str, target: &str) -> bool {
    // Accept a trailing "**" (with optional surrounding slashes) as sugar for
    // "this prefix": strip slashes, then "**", then slashes again.
    let scope = scope
        .trim_end_matches('/')
        .trim_end_matches("**")
        .trim_end_matches('/');
    let granted = normalize(scope);
    // Deny unbounded grants: an empty or root-only normalized scope (from "**",
    // ".", "/", "/**", ...) would otherwise authorize the entire filesystem.
    if !granted
        .components()
        .any(|c| matches!(c, Component::Normal(_)))
    {
        return false;
    }
    let requested = normalize(target);
    requested.starts_with(&granted)
}

fn net_matches(scope: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let scope = scope.to_ascii_lowercase();
    if let Some(suffix) = scope.strip_prefix("*.") {
        if suffix.is_empty() {
            return false; // "*." is not a valid host pattern
        }
        match host.strip_suffix(suffix) {
            Some(prefix) => prefix.ends_with('.') && prefix.len() > 1,
            None => false,
        }
    } else {
        scope == host
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilityClass};
    use crate::request::Request;

    fn cap(line: &str) -> Capability {
        Capability::parse(line).unwrap()
    }

    #[test]
    fn fs_prefix_allows_descendant() {
        let g = cap("fs:read /Users/alice/projects/app");
        let r = Request::new(
            CapabilityClass::FsRead,
            "/Users/alice/projects/app/data.csv",
        );
        assert!(matches(&g, &r));
    }

    #[test]
    fn fs_strips_trailing_glob_suffix() {
        let g = cap("fs:read /Users/alice/projects/app/**");
        let r = Request::new(
            CapabilityClass::FsRead,
            "/Users/alice/projects/app/data.csv",
        );
        assert!(matches(&g, &r));
    }

    #[test]
    fn fs_denies_outside_prefix() {
        let g = cap("fs:read /Users/alice/projects/app");
        let r = Request::new(CapabilityClass::FsRead, "/Users/alice/projects/secrets.txt");
        assert!(!matches(&g, &r));
    }

    #[test]
    fn fs_denies_traversal_escape() {
        let g = cap("fs:read /Users/alice/projects/app");
        let r = Request::new(
            CapabilityClass::FsRead,
            "/Users/alice/projects/app/../secrets.txt",
        );
        assert!(!matches(&g, &r), "../ escape must be denied");
    }

    #[test]
    fn fs_denies_sibling_prefix_confusion() {
        let g = cap("fs:read /a/app");
        let r = Request::new(CapabilityClass::FsRead, "/a/app-secrets/x");
        assert!(!matches(&g, &r));
    }

    #[test]
    fn fs_read_grant_does_not_authorize_write() {
        let g = cap("fs:read /a/b");
        let r = Request::new(CapabilityClass::FsWrite, "/a/b/c");
        assert!(!matches(&g, &r));
    }

    #[test]
    fn net_exact_match() {
        let g = cap("net api.anthropic.com");
        assert!(matches(
            &g,
            &Request::new(CapabilityClass::Net, "api.anthropic.com")
        ));
    }

    #[test]
    fn net_denies_suffix_spoof() {
        let g = cap("net api.anthropic.com");
        assert!(!matches(
            &g,
            &Request::new(CapabilityClass::Net, "api.anthropic.com.evil.com")
        ));
    }

    #[test]
    fn net_wildcard_matches_one_label() {
        let g = cap("net *.anthropic.com");
        assert!(matches(
            &g,
            &Request::new(CapabilityClass::Net, "api.anthropic.com")
        ));
    }

    #[test]
    fn net_wildcard_denies_apex_and_spoof() {
        let g = cap("net *.anthropic.com");
        assert!(!matches(
            &g,
            &Request::new(CapabilityClass::Net, "anthropic.com")
        ));
        assert!(!matches(
            &g,
            &Request::new(CapabilityClass::Net, "anthropic.com.evil.com")
        ));
    }

    #[test]
    fn exec_matches_exact_program() {
        let g = cap("exec git");
        assert!(matches(&g, &Request::new(CapabilityClass::Exec, "git")));
        assert!(!matches(&g, &Request::new(CapabilityClass::Exec, "rm")));
    }

    #[test]
    fn memory_selector_equality() {
        let g = cap("memory:read silo=notes");
        assert!(matches(
            &g,
            &Request::new(CapabilityClass::MemoryRead, "silo=notes")
        ));
        assert!(!matches(
            &g,
            &Request::new(CapabilityClass::MemoryRead, "silo=personal")
        ));
    }

    #[test]
    fn secrets_name_equality() {
        let g = cap("secrets OPENAI_API_KEY");
        assert!(matches(
            &g,
            &Request::new(CapabilityClass::Secrets, "OPENAI_API_KEY")
        ));
        assert!(!matches(
            &g,
            &Request::new(CapabilityClass::Secrets, "AWS_SECRET")
        ));
    }

    #[test]
    fn fs_denies_unbounded_glob() {
        assert!(!matches(
            &cap("fs:read **"),
            &Request::new(CapabilityClass::FsRead, "/etc/shadow")
        ));
    }

    #[test]
    fn fs_denies_bare_root() {
        assert!(!matches(
            &cap("fs:read /"),
            &Request::new(CapabilityClass::FsRead, "/etc/shadow")
        ));
        assert!(!matches(
            &cap("fs:write /**"),
            &Request::new(CapabilityClass::FsWrite, "/etc/shadow")
        ));
    }

    #[test]
    fn fs_desugars_glob_with_trailing_slash() {
        let g = cap("fs:read /a/b/**/");
        assert!(matches(
            &g,
            &Request::new(CapabilityClass::FsRead, "/a/b/c")
        ));
    }

    #[test]
    fn net_is_case_insensitive() {
        let g = cap("net api.anthropic.com");
        assert!(matches(
            &g,
            &Request::new(CapabilityClass::Net, "API.Anthropic.COM")
        ));
    }

    #[test]
    fn net_rejects_bare_wildcard_dot() {
        assert!(!matches(
            &cap("net *."),
            &Request::new(CapabilityClass::Net, "x.")
        ));
    }
}

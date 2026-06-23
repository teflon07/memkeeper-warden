#![forbid(unsafe_code)]
//! warden CLI: `warden serve [--stdio | --socket <path>]`.

mod json;
mod log;
mod serve;

use std::path::{Path, PathBuf};
use warden_core::broker::Broker;
use warden_core::manifest;
use warden_core::policy::Policy;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("serve") => run_serve(&args[1..]),
        Some("log") => log::run(&args[1..]),
        _ => {
            eprintln!("usage: warden serve [--stdio | --socket <path>] [--policy <path>] [--manifests <dir>] [--audit <path>] [--non-interactive]");
            eprintln!("       warden log analyze [--exec] [LOGFILE]");
            2
        }
    };
    std::process::exit(code);
}

fn run_serve(args: &[String]) -> i32 {
    let mut socket: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut manifests_dir: Option<PathBuf> = None;
    let mut audit_path = PathBuf::from(
        std::env::var("WARDEN_AUDIT").unwrap_or_else(|_| default_path("audit.jsonl")),
    );
    let mut interactive = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--stdio" => {}
            "--socket" => {
                i += 1;
                socket = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            "--manifests" => {
                i += 1;
                manifests_dir = args.get(i).map(PathBuf::from);
            }
            "--audit" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    audit_path = PathBuf::from(p);
                }
            }
            "--non-interactive" => interactive = false,
            other => {
                eprintln!("[warden] unknown arg: {other}");
                return 2;
            }
        }
        i += 1;
    }

    let policy = load_policy(policy_path);
    let mut broker = Broker::new(policy, audit_path, interactive);

    if let Some(dir) = &manifests_dir {
        load_manifests(&mut broker, dir);
    }

    match socket {
        Some(path) => serve::run_socket(&mut broker, &path),
        None => serve::run_stdio(&mut broker),
    }
}

fn load_policy(path: Option<PathBuf>) -> Policy {
    let path = path.unwrap_or_else(|| PathBuf::from(default_path("policy.tsv")));
    if let Ok(text) = std::fs::read_to_string(&path) {
        let text = expand_home(&text);
        match Policy::from_text(&text) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "[warden] policy parse error ({}): {e}; starting empty (deny-all)",
                    path.display()
                );
                Policy::default()
            }
        }
    } else {
        eprintln!(
            "[warden] no policy at {}; starting empty (deny-all)",
            path.display()
        );
        Policy::default()
    }
}

/// Scan `<dir>/<skill>/SKILL.md`, registering each skill's declared capabilities.
/// Best-effort: unreadable or nameless entries are skipped.
fn load_manifests(broker: &mut Broker, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!(
            "[warden] no manifests dir at {}; manifest gate inert",
            dir.display()
        );
        return;
    };
    for entry in entries.flatten() {
        let skill_md = entry.path().join("SKILL.md");
        let Ok(doc) = std::fs::read_to_string(&skill_md) else {
            continue;
        };
        // Manifest scopes are matched LEXICALLY against absolute request paths,
        // exactly like policy scopes — so a `$HOME`/`~/` in a SKILL.md capability
        // (e.g. the bundled self-test fixture path) must expand here too, or it
        // would silently match nothing. Mirror load_policy's IO-boundary expansion.
        let doc = expand_home(&doc);
        let Some(name) = manifest::parse_name(&doc) else {
            continue;
        };
        match manifest::parse_capabilities(&doc) {
            Ok(caps) => broker.register_manifest(&name, caps),
            Err(e) => eprintln!("[warden] manifest {}: {e}", skill_md.display()),
        }
    }
}

fn default_path(file: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/.warden/{file}")
}

/// Expand `$HOME` and `~/` in policy text to the absolute home directory.
///
/// Policy scopes are matched LEXICALLY against absolute request paths, so an
/// unexpanded `$HOME/projects` (e.g. from the shipped starter policy) would
/// silently match nothing — granting access to no path at all. Expand at the IO
/// boundary (keeping `Policy::from_text` pure) and log loudly so a misconfigured
/// `HOME` is visible rather than silently producing a deny-everything policy.
fn expand_home(text: &str) -> String {
    expand_home_with(text, std::env::var("HOME").ok().as_deref())
}

/// Pure core of [`expand_home`], split out so it can be tested without mutating
/// the process-global `HOME`. `home` is `None` when `HOME` is unset.
fn expand_home_with(text: &str, home: Option<&str>) -> String {
    if !text.contains("$HOME") && !text.contains("~/") {
        return text.to_string();
    }
    let Some(home) = home else {
        eprintln!(
            "[warden] policy references $HOME/~ but HOME is unset; leaving paths \
             unexpanded — they will match NOTHING (deny-all for those grants)"
        );
        return text.to_string();
    };
    eprintln!("[warden] expanded $HOME/~ -> {home} in policy scopes");
    text.replace("$HOME", home)
        .replace("~/", &format!("{home}/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::capability::CapabilityClass;
    use warden_core::request::Request;

    #[test]
    fn expand_home_replaces_home_token() {
        let home = Some("/home/tester");
        let expanded = expand_home_with("caller\tfs:read\t$HOME/projects\tallow\n", home);
        assert!(
            expanded.contains("/home/tester/projects"),
            "expected $HOME expanded, got: {expanded}"
        );
        assert!(
            !expanded.contains("$HOME"),
            "literal $HOME remained: {expanded}"
        );
        // A leading ~/ form expands too.
        assert!(
            expand_home_with("c\tfs:read\t~/notes\tallow\n", home).contains("/home/tester/notes")
        );
        // Text without the token is returned unchanged.
        assert_eq!(
            expand_home_with("c\tfs:read\t/etc\tallow\n", home),
            "c\tfs:read\t/etc\tallow\n"
        );
        // HOME unset: tokens are left literal (and will match nothing — loud, not silent).
        assert!(expand_home_with("c\tfs:read\t$HOME/x\tallow\n", None).contains("$HOME"));
    }

    #[test]
    fn loads_manifests_and_gates_undeclared() {
        let root = std::env::temp_dir().join("warden_manload");
        let skill_dir = root.join("warden-selftest");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: warden-selftest\ncapabilities:\n  - fs:read /allowed\n---\nbody\n",
        )
        .unwrap();
        let audit = root.join("audit.jsonl");
        let _ = std::fs::remove_file(&audit);

        let mut policy = Policy::default();
        // Grant /etc AND /allowed in policy. /etc/hosts is then policy-allowed,
        // so its denial can ONLY come from the manifest gate — proving
        // load_manifests actually registered warden-selftest's manifest.
        policy.record(
            "warden-selftest",
            warden_core::capability::Capability::parse("fs:read /etc").unwrap(),
            warden_core::policy::Decision::Allow,
        );
        policy.record(
            "warden-selftest",
            warden_core::capability::Capability::parse("fs:read /allowed").unwrap(),
            warden_core::policy::Decision::Allow,
        );
        let mut broker = Broker::new(policy, audit.clone(), false);
        load_manifests(&mut broker, &root);

        let undeclared = Request::new(CapabilityClass::FsRead, "/etc/hosts");
        assert_eq!(
            broker.decide("warden-selftest", &undeclared, "t"),
            warden_core::policy::Decision::Deny
        );
        let declared = Request::new(CapabilityClass::FsRead, "/allowed/x");
        assert_eq!(
            broker.decide("warden-selftest", &declared, "t"),
            warden_core::policy::Decision::Allow
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

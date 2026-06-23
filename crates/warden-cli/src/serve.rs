//! stdio + Unix-socket serve loops. Mirrors `memkeeper serve`: line-delimited
//! JSON, one response per request, 0o600 socket, refuse-to-clobber a live socket.

use crate::json::{parse_request_line, response_line};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use warden_core::broker::Broker;
use warden_core::capability::CapabilityClass;
use warden_core::policy::Decision;
use warden_core::request::Request;

/// Handle one request line against the broker, returning the response line.
pub fn handle_line(broker: &mut Broker, line: &str, ts: &str) -> String {
    let req = match parse_request_line(line) {
        Ok(r) => r,
        Err(e) => return response_line("deny", &format!("bad request: {e}"), None),
    };
    let Some(class) = CapabilityClass::parse(&req.capability) else {
        return response_line("deny", "unknown capability class", None);
    };
    let request = Request::new(class, req.target);
    if req.decide_only {
        let (decision, reason) = broker.decide_verbose(&req.skill, &request, ts);
        return match decision {
            Decision::Allow => response_line("allow", reason, None),
            Decision::Deny => response_line("deny", reason, None),
        };
    }
    match class {
        CapabilityClass::FsRead => match broker.fs_read(&req.skill, &request, ts) {
            Ok(data) => response_line("allow", "policy grant", Some(&data)),
            Err(e) => response_line("deny", &e, None),
        },
        // Non-fs classes: decision only in v1 (forwarders are follow-on work).
        _ => match broker.decide(&req.skill, &request, ts) {
            Decision::Allow => response_line("allow", "policy grant (decision-only in v1)", None),
            Decision::Deny => response_line("deny", "capability_denied", None),
        },
    }
}

/// Run the stdio request loop.
#[must_use]
pub fn run_stdio(broker: &mut Broker) -> i32 {
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return 1 };
        if line.trim().is_empty() {
            continue;
        }
        let ts = now_timestamp();
        let resp = handle_line(broker, &line, &ts);
        if writeln!(out, "{resp}").is_err() || out.flush().is_err() {
            return 1;
        }
    }
    0
}

/// Run the Unix-socket request loop.
#[cfg(unix)]
#[must_use]
pub fn run_socket(broker: &mut Broker, path: &Path) -> i32 {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    if UnixStream::connect(path).is_ok() {
        eprintln!(
            "[warden] another server is already listening on {}",
            path.display()
        );
        return 1;
    }
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[warden] failed to bind {}: {e}", path.display());
            return 1;
        }
    };
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "[warden] failed to restrict {} permissions: {e}",
            path.display()
        );
        return 1;
    }
    eprintln!("[warden] serving on {}", path.display());
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let Ok(read_half) = stream.try_clone() else {
            continue;
        };
        let reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(stream);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            let ts = now_timestamp();
            let resp = handle_line(broker, &line, &ts);
            if writeln!(writer, "{resp}").is_err() || writer.flush().is_err() {
                break;
            }
        }
    }
    0
}

/// Audit timestamp tag from the system clock: `epoch:<unix-seconds>`. RFC3339
/// formatting is deliberate follow-on work (kept dependency-free for v1).
fn now_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("epoch:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::capability::Capability;
    use warden_core::policy::{Decision, Policy};

    fn broker_granting(skill: &str, cap: &str, audit: &Path) -> Broker {
        let mut policy = Policy::default();
        policy.record(skill, Capability::parse(cap).unwrap(), Decision::Allow);
        Broker::new(policy, audit.to_path_buf(), false)
    }

    #[test]
    fn decide_only_fsread_returns_no_data() {
        let audit = std::env::temp_dir().join("warden_serve_do.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_granting("s", "fs:read /a", &audit);
        let line = r#"{"skill":"s","capability":"fs:read","target":"/a/x","decide_only":true}"#;
        let resp = handle_line(&mut b, line, "t");
        assert!(resp.contains("\"decision\":\"allow\""));
        assert!(!resp.contains("\"data\""));
        let _ = std::fs::remove_file(&audit);
    }

    #[test]
    fn decide_only_deny_is_capability_denied() {
        let audit = std::env::temp_dir().join("warden_serve_do_deny.jsonl");
        let _ = std::fs::remove_file(&audit);
        let mut b = broker_granting("s", "fs:read /a", &audit);
        let line = r#"{"skill":"s","capability":"fs:read","target":"/b/x","decide_only":true}"#;
        let resp = handle_line(&mut b, line, "t");
        assert!(resp.contains("\"decision\":\"deny\""));
        assert!(!resp.contains("\"data\""));
        let _ = std::fs::remove_file(&audit);
    }
}

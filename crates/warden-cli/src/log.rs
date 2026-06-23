//! `warden log analyze [--exec] [LOGFILE]`: summarize the gate's dry-run audit
//! log into a go/no-go report for flipping `WARDEN_EXEC_MODE` to enforce.
//!
//! Ported from the former `adapters/claude-code/warden_log_analyze.py` so the
//! reader lives in the same crate as the audit writer and the JSONL field schema
//! (`event`, `decision`, `capability`, `principal`, `target`, `reason`) is not
//! duplicated across two languages. Every `decision: deny` recorded in dry mode
//! is a call that WOULD have been blocked under enforce; every `broker_unreachable`
//! fails closed under enforce; every `exec_unresolved` is a parse gap that also
//! fails closed. This surfaces all three so the enforce flip is data-driven.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::json::field;

/// (principal, capability, target) identifying a would-block row.
type BlockKey = (String, String, String);
/// (count, first-seen reason) for a would-block row.
type BlockVal = (u64, String);

#[derive(Default)]
struct Report {
    decisions: u64,
    by_decision: BTreeMap<String, u64>,
    by_capability: BTreeMap<String, u64>,
    by_principal: BTreeMap<String, u64>,
    blocked: BTreeMap<BlockKey, BlockVal>,
    /// exec-class program -> (allow count, deny count)
    exec_programs: BTreeMap<String, (u64, u64)>,
    exec_no_program: u64,
    exec_unresolved: u64,
    unreachable: u64,
    malformed: u64,
}

fn analyze<I: IntoIterator<Item = String>>(lines: I) -> Report {
    let mut r = Report::default();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('{') {
            r.malformed += 1;
            continue;
        }
        match field(line, "event").as_deref() {
            Some("broker_unreachable") => {
                r.unreachable += 1;
                continue;
            }
            Some("exec_no_program") => {
                r.exec_no_program += 1;
                continue;
            }
            Some("exec_unresolved") => {
                r.exec_unresolved += 1;
                continue;
            }
            Some("decision") => {}
            _ => continue, // unknown/absent event: not counted, mirrors the Python skip
        }

        r.decisions += 1;
        let decision = field(line, "decision").unwrap_or_default();
        let capability = field(line, "capability").unwrap_or_default();
        let principal = field(line, "principal").unwrap_or_default();
        let target = field(line, "target").unwrap_or_default();
        *r.by_decision.entry(decision.clone()).or_default() += 1;
        *r.by_capability.entry(capability.clone()).or_default() += 1;
        *r.by_principal.entry(principal.clone()).or_default() += 1;

        if capability == "exec" && !target.is_empty() {
            let slot = r.exec_programs.entry(target.clone()).or_default();
            if decision == "deny" {
                slot.1 += 1;
            } else {
                slot.0 += 1;
            }
        }

        if decision == "deny" {
            let reason = field(line, "reason").unwrap_or_default();
            let slot = r
                .blocked
                .entry((principal, capability, target))
                .or_insert((0, reason));
            slot.0 += 1;
        }
    }
    r
}

/// would-block rows sorted by descending count, then target.
fn would_block(r: &Report) -> Vec<(&BlockKey, &BlockVal)> {
    let mut rows: Vec<_> = r.blocked.iter().collect();
    rows.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| a.0 .2.cmp(&b.0 .2)));
    rows
}

/// exec programs sorted by descending total, then name.
fn exec_rows(r: &Report) -> Vec<(&String, &(u64, u64))> {
    let mut rows: Vec<_> = r.exec_programs.iter().collect();
    rows.sort_by(|a, b| {
        let (ta, tb) = (a.1 .0 + a.1 .1, b.1 .0 + b.1 .1);
        tb.cmp(&ta).then_with(|| a.0.cmp(b.0))
    });
    rows
}

fn format_report(r: &Report) -> String {
    let mut out = vec!["=== Warden dry-run analysis ===".to_string()];
    out.push(format!(
        "decisions: {}  (allow={}, deny={})",
        r.decisions,
        r.by_decision.get("allow").copied().unwrap_or(0),
        r.by_decision.get("deny").copied().unwrap_or(0),
    ));
    out.push(format!(
        "broker_unreachable: {}{}",
        r.unreachable,
        if r.unreachable > 0 {
            "   <- fails CLOSED under enforce"
        } else {
            ""
        },
    ));
    if r.malformed > 0 {
        out.push(format!("malformed lines skipped: {}", r.malformed));
    }

    out.push(String::new());
    out.push(format!("by capability: {}", join_counts(&r.by_capability)));
    out.push(format!("by principal:  {}", join_counts(&r.by_principal)));

    out.push(String::new());
    let wb = would_block(r);
    if wb.is_empty() {
        out.push("WOULD-BLOCK: none. No denies in dry mode — clean to enforce.".to_string());
    } else {
        out.push(format!(
            "WOULD-BLOCK ({} distinct targets) — each must be granted in policy or confirmed-blocked before enforce:",
            wb.len()
        ));
        for ((principal, capability, target), (count, reason)) in wb {
            out.push(format!(
                "  [{count:>3}x] {principal} {capability} {target}  ({reason})"
            ));
        }
    }
    out.join("\n")
}

fn format_exec_report(r: &Report) -> String {
    let rows = exec_rows(r);
    let total: u64 = r.exec_programs.values().map(|(a, d)| a + d).sum();
    let mut out = vec!["=== Warden exec-gate review (dry-run audit) ===".to_string()];
    out.push(format!(
        "exec decisions: {}   distinct programs: {}",
        total,
        r.exec_programs.len()
    ));
    out.push(format!(
        "unparsed Bash commands (no program extracted): {}",
        r.exec_no_program
    ));
    out.push(format!(
        "unresolved parse gaps (fail CLOSED under enforce): {}",
        r.exec_unresolved
    ));
    out.push(format!(
        "broker_unreachable (all classes): {}{}",
        r.unreachable,
        if r.unreachable > 0 {
            "   <- fails CLOSED under enforce"
        } else {
            ""
        },
    ));

    out.push(String::new());
    if rows.is_empty() {
        out.push(
            "No exec decisions recorded. Either no Bash ran or the gate isn't observing — \
check WARDEN_EXEC_MODE is dry/enforce, not off."
                .to_string(),
        );
        return out.join("\n");
    }

    out.push("programs observed (by frequency):".to_string());
    for (prog, (allow, deny)) in &rows {
        out.push(format!(
            "  [{:>4}x] {prog}  (allow={allow} deny={deny})",
            allow + deny
        ));
    }

    out.push(String::new());
    out.push(
        "candidate grants — review, then append the keepers to ~/.warden/policy.tsv".to_string(),
    );
    out.push(
        "(restart the daemon to load; deliberately omit anything you want blocked):".to_string(),
    );
    for (prog, _) in &rows {
        out.push(format!("  claude-code-main\texec\t{prog}\tallow"));
    }
    out.join("\n")
}

fn join_counts(m: &BTreeMap<String, u64>) -> String {
    if m.is_empty() {
        return "(none)".to_string();
    }
    m.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn default_log_path() -> PathBuf {
    if let Ok(dir) = std::env::var("WARDEN_STATE_DIR") {
        return PathBuf::from(dir).join("warden-gate.log");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".claude/hooks/state/warden-gate.log")
}

/// `warden log analyze [--exec] [LOGFILE]`. `analyze` is the only verb and may be
/// omitted. Returns a process exit code.
pub fn run(args: &[String]) -> i32 {
    let mut exec_view = false;
    let mut logfile: Option<PathBuf> = None;
    for a in args {
        match a.as_str() {
            "analyze" => {} // the only verb; accepted explicitly or implied
            "--exec" => exec_view = true,
            other if other.starts_with('-') => {
                eprintln!("[warden] unknown arg: {other}");
                return 2;
            }
            other => logfile = Some(PathBuf::from(other)),
        }
    }

    let path = logfile.unwrap_or_else(default_log_path);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("warden log: no log at {}", path.display());
        return 1;
    };

    let report = analyze(text.lines().map(str::to_string));
    let rendered = if exec_view {
        format_exec_report(&report)
    } else {
        format_report(&report)
    };
    println!("{rendered}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(event: &str, extra: &str) -> String {
        format!("{{\"principal\": \"claude-code-main\", \"event\": \"{event}\"{extra}}}")
    }

    #[test]
    fn counts_decisions_and_would_block() {
        let log = vec![
            line(
                "decision",
                ", \"capability\": \"exec\", \"target\": \"git\", \"decision\": \"allow\", \"reason\": \"granted\"",
            ),
            line(
                "decision",
                ", \"capability\": \"exec\", \"target\": \"rm\", \"decision\": \"deny\", \"reason\": \"no grant\"",
            ),
            line(
                "decision",
                ", \"capability\": \"exec\", \"target\": \"rm\", \"decision\": \"deny\", \"reason\": \"no grant\"",
            ),
            line("broker_unreachable", ", \"capability\": \"exec\", \"target\": \"curl\""),
            line("exec_no_program", ", \"command\": \"cd /tmp\""),
            line("exec_unresolved", ", \"command\": \"$CMD x\""),
            "not json".to_string(),
            String::new(),
        ];
        let r = analyze(log);
        assert_eq!(r.decisions, 3);
        assert_eq!(r.by_decision.get("allow").copied(), Some(1));
        assert_eq!(r.by_decision.get("deny").copied(), Some(2));
        assert_eq!(r.unreachable, 1);
        assert_eq!(r.exec_no_program, 1);
        assert_eq!(r.exec_unresolved, 1);
        assert_eq!(r.malformed, 1);
        // rm denied twice -> single would-block row with count 2.
        let wb = would_block(&r);
        assert_eq!(wb.len(), 1);
        assert_eq!(wb[0].1 .0, 2);
        assert_eq!(wb[0].0 .2, "rm");
    }

    #[test]
    fn exec_programs_split_allow_deny() {
        let log = vec![
            line(
                "decision",
                ", \"capability\": \"exec\", \"target\": \"git\", \"decision\": \"allow\", \"reason\": \"\"",
            ),
            line(
                "decision",
                ", \"capability\": \"exec\", \"target\": \"git\", \"decision\": \"allow\", \"reason\": \"\"",
            ),
            line(
                "decision",
                ", \"capability\": \"exec\", \"target\": \"git\", \"decision\": \"deny\", \"reason\": \"x\"",
            ),
        ];
        let r = analyze(log);
        assert_eq!(r.exec_programs.get("git").copied(), Some((2, 1)));
        let report = format_exec_report(&r);
        assert!(report.contains("(allow=2 deny=1)"));
        assert!(report.contains("claude-code-main\texec\tgit\tallow"));
    }

    #[test]
    fn clean_log_reports_clean_to_enforce() {
        let log = vec![line(
            "decision",
            ", \"capability\": \"exec\", \"target\": \"git\", \"decision\": \"allow\", \"reason\": \"granted\"",
        )];
        let r = analyze(log);
        assert!(format_report(&r).contains("clean to enforce"));
    }

    #[test]
    fn unreachable_flagged_fail_closed() {
        let log = vec![line(
            "broker_unreachable",
            ", \"capability\": \"exec\", \"target\": \"x\"",
        )];
        let r = analyze(log);
        assert!(format_report(&r).contains("fails CLOSED under enforce"));
    }
}

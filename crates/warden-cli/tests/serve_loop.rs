//! End-to-end: a granted skill reads an in-scope file; an out-of-scope read is denied.

use std::io::Write;
use std::process::{Command, Stdio};

fn warden_bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // memkeeper
    p.push("target/debug/warden");
    p
}

#[test]
fn stdio_allows_in_scope_and_denies_out_of_scope() {
    let dir = std::env::temp_dir().join("warden_serve_it");
    std::fs::create_dir_all(&dir).unwrap();
    let data = dir.join("ok.txt");
    std::fs::write(&data, b"payload").unwrap();
    let policy = dir.join("policy.tsv");
    std::fs::write(&policy, format!("s\tfs:read\t{}\tallow\n", dir.display())).unwrap();
    let audit = dir.join("audit.jsonl");

    let mut child = Command::new(warden_bin())
        .args(["serve", "--stdio", "--policy"])
        .arg(&policy)
        .arg("--audit")
        .arg(&audit)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn warden");

    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{{\"skill\":\"s\",\"capability\":\"fs:read\",\"target\":\"{}\"}}",
        data.display()
    )
    .unwrap();
    writeln!(
        stdin,
        "{{\"skill\":\"s\",\"capability\":\"fs:read\",\"target\":\"/etc/hosts\"}}"
    )
    .unwrap();
    drop(stdin);

    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[0].contains("\"decision\":\"allow\""),
        "line0: {}",
        lines[0]
    );
    assert!(lines[0].contains("payload"));
    assert!(
        lines[1].contains("\"decision\":\"deny\""),
        "line1: {}",
        lines[1]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

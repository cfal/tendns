use std::{fs, process::Command};

use hickory_proto::rr::Name;
use tendns::{
    config::Config,
    protocol::{Secret, Value, decrypt},
    resolver::{Clock, SystemClock},
};

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

#[test]
fn offline_cli_generates_roundtrippable_mixed_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tendns.toml");
    fs::write(
        &path,
        format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}'"),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_tendns"))
        .args([
            "--config",
            path.to_str().unwrap(),
            "txt",
            "--name",
            "EXAMPLE.COM",
            "--entry",
            "@:A:192.0.2.1",
            "--entry",
            "nas:AAAA:2001:db8::1",
            "--entry",
            "www:CNAME:target.net",
            "--valid-for",
            "1h",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let output = String::from_utf8(result.stdout).unwrap();
    assert_eq!(output.lines().count(), 1);
    assert!(output.starts_with("td1."));
    assert!(!output.contains(KEY));
    let config = Config::load(&path).unwrap();
    let owner = Name::from_ascii("example.com.").unwrap();
    let publication = decrypt(
        output.trim().as_bytes(),
        &config.discovery[0].key,
        &owner,
        SystemClock.now().unwrap(),
    )
    .unwrap();
    assert_eq!(publication.entries.len(), 3);
    assert_eq!(publication.expires_at - publication.issued_at, 3600);
    assert!(matches!(publication.entries[2].value, Value::Cname(_)));
    assert_eq!(publication.entries[1].subdomain, "nas");
    let invalid = Command::new(env!("CARGO_BIN_EXE_tendns"))
        .args([
            "--config",
            path.to_str().unwrap(),
            "txt",
            "--name",
            "example.com",
            "--a",
            "192.0.2.1",
            "--cname",
            "target.net",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains(KEY));
    let subdomain = Command::new(env!("CARGO_BIN_EXE_tendns"))
        .args([
            "--config",
            path.to_str().unwrap(),
            "txt",
            "--name",
            "example.com",
            "--subdomain",
            "NAS",
            "--a",
            "192.0.2.3",
        ])
        .output()
        .unwrap();
    assert!(subdomain.status.success());
    let publication = decrypt(
        String::from_utf8(subdomain.stdout)
            .unwrap()
            .trim()
            .as_bytes(),
        &config.discovery[0].key,
        &owner,
        SystemClock.now().unwrap(),
    )
    .unwrap();
    assert_eq!(publication.entries[0].subdomain, "nas");
}

#[test]
fn keygen_needs_no_config_and_does_not_repeat() {
    let mut keys = Vec::new();
    for _ in 0..2 {
        let result = Command::new(env!("CARGO_BIN_EXE_tendns"))
            .args(["--config", "/nonexistent/config", "keygen"])
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        let key = String::from_utf8(result.stdout).unwrap();
        assert_eq!(key.trim().len(), 43);
        Secret::decode(key.trim()).unwrap();
        keys.push(key);
    }
    assert_ne!(keys[0], keys[1]);
}

//! `--run` and the dashboard, with the real binary: a (harmless) shell-script "sample" makes
//! a request and exits; meanwhile the dashboard is checked; afterwards, run.json & report.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// One HTTP/1.1 request; returns (status line + headers, body)
async fn get(port: u16, path: &str, headers: &str) -> Option<(String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{headers}\r\n").as_bytes()).await.ok()?;
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response)).await.ok()?.ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    Some((head.to_string(), body.to_string()))
}

#[tokio::test]
async fn runs_a_sample_and_serves_the_dashboard() {
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("run-and-dashboard");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let (http, health) = (free_port(), free_port());
    let secret = "0123456789abcdef0123456789abcdef-dashboard";
    std::fs::write(work.join("link.secret"), secret).unwrap();
    std::fs::write(work.join("fakenet.toml"), format!(
        "[nucleus]\nbind = \"127.0.0.1\"\ncapture_dir = \"runs\"\nhealth = \"127.0.0.1:{health}\"\n[daemon]\nwebsocket_url = \"\"\nhttp_url = \"\"\nsecret_file = \"link.secret\"\n[[listener]]\nname = \"HTTP\"\nprotocol = \"http\"\nport = {http}\n"
    )).unwrap();
    // The "sample": waits for the dashboard checks, beacons, exits with code 3
    let sample = work.join("beacon.sh");
    std::fs::write(&sample, format!("#!/bin/sh\nsleep 2\ncurl -s -o /dev/null http://127.0.0.1:{http}/beacon.php?id=1\nsleep 1\nexit 3\n")).unwrap();
    std::fs::set_permissions(&sample, std::fs::Permissions::from_mode(0o755)).unwrap();

    let nucleus = Command::new(env!("CARGO_BIN_EXE_fakenet-nucleus"))
        .args(["-c", work.join("fakenet.toml").to_str().unwrap(), "--run", sample.to_str().unwrap(), "--timeout", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // The dashboard, while the sample runs
    let deadline = Instant::now() + Duration::from_secs(20);
    while get(health, "/health", "").await.is_none() {
        assert!(Instant::now() < deadline, "the nucleus never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (head, _) = get(health, "/dashboard", "").await.unwrap();
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    let (head, _) = get(health, &format!("/dashboard?token={secret}"), "").await.unwrap();
    assert!(head.starts_with("HTTP/1.1 303") && head.contains("location: /dashboard"), "{head}");
    let cookie = head.lines().find_map(|l| l.strip_prefix("set-cookie: ")).unwrap().split(';').next().unwrap().to_string();
    assert!(head.contains("HttpOnly; SameSite=Strict"));
    let (head, page) = get(health, "/dashboard", &format!("Cookie: {cookie}\r\n")).await.unwrap();
    assert!(head.starts_with("HTTP/1.1 200") && page.contains("<script src=\"/dashboard.js\""), "{head}");
    assert!(head.contains("content-security-policy: default-src 'none'; script-src 'self'"));
    let (_, script) = get(health, "/dashboard.js", "").await.unwrap();
    assert!(!script.contains("innerHTML") && !script.contains("insertAdjacentHTML") && !script.contains("eval("));
    let (head, _) = get(health, "/api/records", "").await.unwrap();
    assert!(head.starts_with("HTTP/1.1 401"));
    // The sample's beacon shows up in the records API
    let mut seen = false;
    while !seen && Instant::now() < deadline {
        let (_, body) = get(health, "/api/records?after=0", &format!("Authorization: Bearer {secret}\r\n")).await.unwrap();
        seen = body.contains("/beacon.php?id=1");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(seen, "the beacon never reached the records API");
    let (_, summary) = get(health, "/api/summary", &format!("Cookie: {cookie}\r\n")).await.unwrap();
    assert!(summary.contains("\"listeners\""), "{summary}");

    // The run ends by itself after the sample exits (plus the grace period)
    let status = tokio::task::spawn_blocking(move || nucleus.wait_with_output()).await.unwrap().unwrap();
    assert!(status.status.success());
    let runs: Vec<_> = std::fs::read_dir(work.join("runs")).unwrap().flatten().collect();
    assert_eq!(runs.len(), 1);
    let folder = runs[0].path();
    assert!(folder.file_name().unwrap().to_string_lossy().contains("-beacon.sh-"));
    let run: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(folder.join("run.json")).unwrap()).unwrap();
    assert_eq!(run["run"]["ended_by"], "exited");
    assert!(run["run"]["exit"].as_str().unwrap().contains('3'), "{run:#}");
    assert_eq!(run["sample"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(run["sample"]["md5"].as_str().unwrap().len(), 32);
    assert!(run["events_by_protocol"]["http"].as_u64().unwrap() >= 1, "{run:#}");
    let events = std::fs::read_to_string(folder.join("events.jsonl")).unwrap();
    assert!(events.contains("\"kind\":\"sample_started\"") && events.contains("\"kind\":\"sample_exited\""));
    assert!(folder.join("report.html").exists());
}

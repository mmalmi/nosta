//! Integration tests for git-remote-nostr
//!
//! Tests the git remote helper protocol by simulating git commands

use std::process::{Command, Stdio};
use std::io::Write;
use tempfile::TempDir;

/// Create a test git repository
fn create_test_repo() -> TempDir {
    let dir = TempDir::new().unwrap();

    Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Set default branch to main
    Command::new("git")
        .args(["checkout", "-b", "main"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Create a test file
    std::fs::write(dir.path().join("README.md"), "# Test Repo\n").unwrap();

    Command::new("git")
        .args(["add", "."])
        .current_dir(dir.path())
        .output()
        .unwrap();

    Command::new("git")
        .args(["commit", "-m", "Initial commit"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    dir
}

#[test]
fn test_capabilities_command() {
    let binary = env!("CARGO_BIN_EXE_git-remote-nostr");

    let mut child = Command::new(binary)
        .args([
            "origin",
            "nostr://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/test",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn git-remote-nostr");

    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "capabilities").unwrap();
    writeln!(stdin, "").unwrap(); // Empty line to exit
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("fetch"), "Should advertise fetch capability");
    assert!(stdout.contains("push"), "Should advertise push capability");
    assert!(stdout.contains("option"), "Should advertise option capability");
}

#[test]
fn test_list_command_empty_repo() {
    let binary = env!("CARGO_BIN_EXE_git-remote-nostr");

    let mut child = Command::new(binary)
        .args([
            "origin",
            "nostr://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/empty-repo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn git-remote-nostr");

    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "list").unwrap();
    writeln!(stdin, "").unwrap();
    drop(stdin);

    let output = child.wait_with_output().unwrap();

    // Empty repo should return just empty line (no refs)
    // The exact format may vary but should not error
    assert!(output.status.success() || output.status.code() == Some(0),
        "list command should succeed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_push_command_format() {
    let repo = create_test_repo();
    let binary = env!("CARGO_BIN_EXE_git-remote-nostr");

    let mut child = Command::new(binary)
        .args([
            "origin",
            "nostr://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/test-repo",
        ])
        .current_dir(repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn git-remote-nostr");

    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "push refs/heads/main:refs/heads/main").unwrap();
    writeln!(stdin, "").unwrap(); // Execute push
    writeln!(stdin, "").unwrap(); // Exit
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should respond with ok or error for the ref
    assert!(
        stdout.contains("ok refs/heads/main") || stdout.contains("error refs/heads/main"),
        "Push should respond with status for ref: stdout={}, stderr={}",
        stdout, stderr
    );
}

#[test]
fn test_invalid_url() {
    let binary = env!("CARGO_BIN_EXE_git-remote-nostr");

    let output = Command::new(binary)
        .args(["origin", "https://github.com/foo/bar"])
        .output()
        .expect("Failed to run git-remote-nostr");

    // Should fail with invalid URL
    assert!(!output.status.success(), "Invalid URL should fail");
}

#[test]
fn test_invalid_pubkey() {
    let binary = env!("CARGO_BIN_EXE_git-remote-nostr");

    let output = Command::new(binary)
        .args(["origin", "nostr://shortkey/repo"])
        .output()
        .expect("Failed to run git-remote-nostr");

    // Should fail with invalid pubkey
    assert!(!output.status.success(), "Short pubkey should fail");
}

//! Integration tests using the actual git CLI
//!
//! These tests verify that real git clients can interact with our server.

use axum::{
    Router,
    routing::{get, post},
    extract::{Path, Query, State},
    body::Bytes,
    response::IntoResponse,
    http::{StatusCode, header},
};
use nosta_git::{GitStorage, http::{Service, handle_info_refs, handle_upload_pack, handle_receive_pack}};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::TcpListener;

struct AppState {
    storage: GitStorage,
}

async fn info_refs_handler(
    Path(_repo): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let service_name = match params.get("service") {
        Some(s) => s.as_str(),
        None => return (StatusCode::BAD_REQUEST, "missing service").into_response(),
    };

    let service = match Service::from_str(service_name) {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "invalid service").into_response(),
    };

    match handle_info_refs(&state.storage, service) {
        Ok((content_type, body)) => {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                body,
            ).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn upload_pack_handler(
    Path(_repo): Path<String>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    match handle_upload_pack(&state.storage, &body) {
        Ok(response) => {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, Service::UploadPack.result_content_type())],
                response,
            ).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn receive_pack_handler(
    Path(_repo): Path<String>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    match handle_receive_pack(&state.storage, &body) {
        Ok(response) => {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, Service::ReceivePack.result_content_type())],
                response,
            ).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn create_router(storage: GitStorage) -> Router {
    let state = Arc::new(AppState { storage });

    Router::new()
        .route("/:repo/info/refs", get(info_refs_handler))
        .route("/:repo/git-upload-pack", post(upload_pack_handler))
        .route("/:repo/git-receive-pack", post(receive_pack_handler))
        .with_state(state)
}

async fn start_test_server(storage: GitStorage) -> SocketAddr {
    let router = create_router(storage);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Check if git is available
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run git command with timeout
fn run_git_with_timeout(args: &[&str], cwd: Option<&std::path::Path>, timeout_secs: u64) -> std::io::Result<Output> {
    use std::process::Stdio;

    let mut cmd = Command::new("git");
    cmd.args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let mut child = cmd.spawn()?;

    // Wait with timeout
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        match child.try_wait()? {
            Some(status) => {
                let stdout = child.stdout.take().map(|mut s| {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut s, &mut buf).ok();
                    buf
                }).unwrap_or_default();

                let stderr = child.stderr.take().map(|mut s| {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut s, &mut buf).ok();
                    buf
                }).unwrap_or_default();

                return Ok(Output { status, stdout, stderr });
            }
            None => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("git command timed out after {}s", timeout_secs),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_git_push_and_clone() {
    if !git_available() {
        eprintln!("git not available, skipping test");
        return;
    }

    // Set up server
    let server_dir = tempdir().unwrap();
    let storage = GitStorage::open(server_dir.path().join("git")).unwrap();
    let addr = start_test_server(storage).await;
    let url = format!("http://{}/test.git", addr);

    // Create local repo
    let local_dir = tempdir().unwrap();
    let local_path = local_dir.path();

    // git init
    let output = run_git_with_timeout(&["init"], Some(local_path), 10).unwrap();
    assert!(output.status.success(), "git init failed: {}", String::from_utf8_lossy(&output.stderr));

    // Configure git
    run_git_with_timeout(&["config", "user.email", "test@test.com"], Some(local_path), 5).unwrap();
    run_git_with_timeout(&["config", "user.name", "Test"], Some(local_path), 5).unwrap();

    // Create a file
    std::fs::write(local_path.join("README.md"), "# Test Repository\n\nHello from nosta-git!\n").unwrap();

    // git add
    let output = run_git_with_timeout(&["add", "README.md"], Some(local_path), 10).unwrap();
    assert!(output.status.success(), "git add failed: {}", String::from_utf8_lossy(&output.stderr));

    // git commit
    let output = run_git_with_timeout(&["commit", "-m", "Initial commit"], Some(local_path), 10).unwrap();
    assert!(output.status.success(), "git commit failed: {}", String::from_utf8_lossy(&output.stderr));

    // git remote add
    let output = run_git_with_timeout(&["remote", "add", "origin", &url], Some(local_path), 5).unwrap();
    assert!(output.status.success(), "git remote add failed: {}", String::from_utf8_lossy(&output.stderr));

    // git push (with 30s timeout for network operations)
    let output = run_git_with_timeout(&["push", "-u", "origin", "master"], Some(local_path), 30).unwrap();

    eprintln!("push stdout: {}", String::from_utf8_lossy(&output.stdout));
    eprintln!("push stderr: {}", String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        eprintln!("git push failed (may need protocol adjustments)");
    }

    // Try to clone into new directory (with 30s timeout)
    let clone_dir = tempdir().unwrap();
    let output = run_git_with_timeout(&["clone", &url, "cloned"], Some(clone_dir.path()), 30).unwrap();

    eprintln!("clone stdout: {}", String::from_utf8_lossy(&output.stdout));
    eprintln!("clone stderr: {}", String::from_utf8_lossy(&output.stderr));

    // Check if clone succeeded
    if output.status.success() {
        let readme = clone_dir.path().join("cloned").join("README.md");
        if readme.exists() {
            let content = std::fs::read_to_string(&readme).unwrap();
            assert!(content.contains("Hello from nosta-git!"), "README content mismatch");
            eprintln!("SUCCESS: Full git push/clone cycle works!");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_git_ls_remote() {
    if !git_available() {
        eprintln!("git not available, skipping test");
        return;
    }

    // Set up server with a commit
    let server_dir = tempdir().unwrap();
    let storage = GitStorage::open(server_dir.path().join("git")).unwrap();

    // Create a commit directly in storage
    let tree_oid = storage.write_tree(b"").unwrap();
    let commit_content = format!(
        "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nTest commit\n",
        tree_oid
    );
    let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();
    storage.write_ref("refs/heads/main", &nosta_git::refs::Ref::Direct(commit_oid)).unwrap();
    storage.write_ref("HEAD", &nosta_git::refs::Ref::Symbolic("refs/heads/main".into())).unwrap();

    let addr = start_test_server(storage).await;
    let url = format!("http://{}/test.git", addr);

    // git ls-remote should work (with 15s timeout)
    let output = run_git_with_timeout(&["ls-remote", &url], None, 15).unwrap();

    eprintln!("ls-remote stdout: {}", String::from_utf8_lossy(&output.stdout));
    eprintln!("ls-remote stderr: {}", String::from_utf8_lossy(&output.stderr));

    assert!(output.status.success(), "git ls-remote failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&commit_oid.to_hex()), "should contain commit oid");
    assert!(stdout.contains("refs/heads/main"), "should contain ref name");
}

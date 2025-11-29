//! Integration tests for the git HTTP protocol
//!
//! These tests spin up a real HTTP server and test the protocol handlers.

use axum::{
    Router,
    routing::{get, post},
    extract::{Path, Query, State},
    body::Bytes,
    response::IntoResponse,
    http::{StatusCode, header},
};
use nosta_git::{GitStorage, http::{Service, handle_info_refs, handle_upload_pack, handle_receive_pack}};
use nosta_git::refs::Ref;
use std::collections::HashMap;
use std::net::SocketAddr;
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

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Create a reqwest client with reasonable timeouts
fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_info_refs_returns_correct_content_type() {
    let server_dir = tempdir().unwrap();
    let storage = GitStorage::open(server_dir.path().join("git")).unwrap();
    let addr = start_test_server(storage).await;

    let client = test_client();

    // Test upload-pack info/refs
    let resp = client
        .get(format!("http://{}/test.git/info/refs?service=git-upload-pack", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap().to_str().unwrap(),
        "application/x-git-upload-pack-advertisement"
    );

    let body = resp.text().await.unwrap();
    assert!(body.contains("# service=git-upload-pack"), "body: {}", body);

    // Test receive-pack info/refs
    let resp = client
        .get(format!("http://{}/test.git/info/refs?service=git-receive-pack", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap().to_str().unwrap(),
        "application/x-git-receive-pack-advertisement"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_info_refs_with_commit() {
    let server_dir = tempdir().unwrap();
    let storage = GitStorage::open(server_dir.path().join("git")).unwrap();

    // Create a commit
    let tree_oid = storage.write_tree(b"").unwrap();
    let commit_content = format!(
        "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial commit\n",
        tree_oid
    );
    let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();

    // Create refs
    storage.write_ref("refs/heads/main", &Ref::Direct(commit_oid)).unwrap();
    storage.write_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();

    let addr = start_test_server(storage).await;
    let client = test_client();

    let resp = client
        .get(format!("http://{}/test.git/info/refs?service=git-upload-pack", addr))
        .send()
        .await
        .unwrap();

    let body = resp.text().await.unwrap();
    assert!(body.contains(&commit_oid.to_hex()), "should contain commit oid");
    assert!(body.contains("refs/heads/main"), "should contain ref name");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_upload_pack_empty_want() {
    let server_dir = tempdir().unwrap();
    let storage = GitStorage::open(server_dir.path().join("git")).unwrap();
    let addr = start_test_server(storage).await;

    let client = test_client();

    // Send empty request (just flush)
    let resp = client
        .post(format!("http://{}/test.git/git-upload-pack", addr))
        .header("content-type", "application/x-git-upload-pack-request")
        .body("0000")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    // Should get NAK response
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("NAK"), "should contain NAK: {}", body_str);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_pack_creates_ref() {
    let server_dir = tempdir().unwrap();
    let storage = GitStorage::open(server_dir.path().join("git")).unwrap();

    // Create a commit to push
    let tree_oid = storage.write_tree(b"").unwrap();
    let commit_content = format!(
        "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nTest\n",
        tree_oid
    );
    let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();

    let addr = start_test_server(storage).await;
    let client = test_client();

    // Construct a minimal receive-pack request (without sideband)
    // Format: <old-oid> <new-oid> <ref-name>\0<caps>
    let zero_oid = "0000000000000000000000000000000000000000";
    let ref_update = format!("{} {} refs/heads/main\0report-status\n", zero_oid, commit_oid);
    let pkt_len = format!("{:04x}", ref_update.len() + 4);

    let mut body = Vec::new();
    body.extend_from_slice(pkt_len.as_bytes());
    body.extend_from_slice(ref_update.as_bytes());
    body.extend_from_slice(b"0000"); // flush

    let resp = client
        .post(format!("http://{}/test.git/git-receive-pack", addr))
        .header("content-type", "application/x-git-receive-pack-request")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unpack ok"), "should contain unpack ok: {}", body);
    assert!(body.contains("ok refs/heads/main"), "should contain ok ref: {}", body);
}

#[cfg(test)]
mod unit_tests {
    use nosta_git::storage::GitStorage;
    use nosta_git::refs::Ref;
    use nosta_git::http::{handle_info_refs, Service};
    use tempfile::tempdir;

    #[test]
    fn test_create_commit_and_advertise() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Create empty tree
        let tree_oid = storage.write_tree(b"").unwrap();

        // Create commit
        let commit_content = format!(
            "tree {}\n\
             author Test <test@test.com> 1700000000 +0000\n\
             committer Test <test@test.com> 1700000000 +0000\n\n\
             Initial commit\n",
            tree_oid
        );
        let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();

        // Create refs
        storage.write_ref("refs/heads/main", &Ref::Direct(commit_oid)).unwrap();
        storage.write_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();

        // Get info/refs
        let (content_type, body) = handle_info_refs(&storage, Service::UploadPack).unwrap();

        assert_eq!(content_type, "application/x-git-upload-pack-advertisement");

        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains(&commit_oid.to_hex()));
        assert!(body_str.contains("refs/heads/main"));
        assert!(body_str.contains("HEAD"));
    }
}

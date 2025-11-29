//! Minimal git HTTP server for testing
//!
//! Run with: cargo run -p nosta-git --example server
//! Then test with: git ls-remote http://127.0.0.1:9999/test.git

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
use std::sync::Arc;
use tokio::net::TcpListener;

struct AppState {
    storage: GitStorage,
}

async fn info_refs_handler(
    Path(repo): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    eprintln!("INFO_REFS: repo={}, params={:?}", repo, params);

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
            eprintln!("INFO_REFS response: {} bytes", body.len());
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                body,
            ).into_response()
        }
        Err(e) => {
            eprintln!("INFO_REFS error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn upload_pack_handler(
    Path(repo): Path<String>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    eprintln!("UPLOAD_PACK: repo={}, body_len={}", repo, body.len());
    eprintln!("UPLOAD_PACK body: {:?}", String::from_utf8_lossy(&body));

    match handle_upload_pack(&state.storage, &body) {
        Ok(response) => {
            eprintln!("UPLOAD_PACK response: {} bytes", response.len());
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, Service::UploadPack.result_content_type())],
                response,
            ).into_response()
        }
        Err(e) => {
            eprintln!("UPLOAD_PACK error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn receive_pack_handler(
    Path(repo): Path<String>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    eprintln!("RECEIVE_PACK: repo={}, body_len={}", repo, body.len());
    eprintln!("RECEIVE_PACK body hex: {:02x?}", &body[..std::cmp::min(200, body.len())]);
    eprintln!("RECEIVE_PACK body str: {:?}", String::from_utf8_lossy(&body[..std::cmp::min(200, body.len())]));

    match handle_receive_pack(&state.storage, &body) {
        Ok(response) => {
            eprintln!("RECEIVE_PACK response: {} bytes", response.len());
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, Service::ReceivePack.result_content_type())],
                response,
            ).into_response()
        }
        Err(e) => {
            eprintln!("RECEIVE_PACK error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create storage in temp dir
    let storage_path = std::env::temp_dir().join("nosta-git-test");
    std::fs::create_dir_all(&storage_path)?;

    let storage = GitStorage::open(&storage_path)?;

    // Start with empty repo (no initial commit)
    eprintln!("Starting with empty repository");
    eprintln!("Storage path: {}", storage_path.display());

    let state = Arc::new(AppState { storage });

    let app = Router::new()
        .route("/:repo/info/refs", get(info_refs_handler))
        .route("/:repo/git-upload-pack", post(upload_pack_handler))
        .route("/:repo/git-receive-pack", post(receive_pack_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:9999").await?;
    eprintln!("Server running on http://127.0.0.1:9999");
    eprintln!("Test with: git ls-remote http://127.0.0.1:9999/test.git");

    axum::serve(listener, app).await?;
    Ok(())
}

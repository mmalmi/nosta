mod auth;
pub mod blossom;
mod git;
mod handlers;
mod mime;
pub mod stun;
mod ui;

use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{any, get, post, put},
    Router,
};
use crate::storage::NostaStore;
use nosta_git::GitStorage;
use nostrdb::Ndb;
use nosta_relay::{ws_handler, RelayState};
use std::sync::Arc;

pub use auth::{AppState, AuthCredentials};

pub struct NostaServer {
    state: AppState,
    relay_state: Option<RelayState>,
    git_storage: Option<Arc<GitStorage>>,
    local_pubkey: Option<String>,
    addr: String,
}

impl NostaServer {
    pub fn new(store: Arc<NostaStore>, addr: String) -> Self {
        Self {
            state: AppState {
                store,
                auth: None,
                ndb_query: None,
            },
            relay_state: None,
            git_storage: None,
            local_pubkey: None,
            addr,
        }
    }

    /// Enable git smart HTTP protocol
    pub fn with_git(mut self, storage: Arc<GitStorage>, local_pubkey: String) -> Self {
        self.git_storage = Some(storage);
        self.local_pubkey = Some(local_pubkey);
        self
    }

    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.state.auth = Some(AuthCredentials { username, password });
        self
    }

    pub fn with_ndb(mut self, ndb: Ndb) -> Self {
        self.relay_state = Some(RelayState {
            ndb: Arc::new(ndb),
            max_write_distance: None, // No restriction by default
        });
        self
    }

    /// Set maximum follow distance for write access to the relay
    /// distance 0 = only root user, 1 = root + direct follows, etc.
    /// None = no restriction (anyone can write)
    pub fn with_max_write_distance(mut self, max_distance: Option<u32>) -> Self {
        if let Some(ref mut state) = self.relay_state {
            state.max_write_distance = max_distance;
        }
        self
    }

    pub fn with_ndb_query(mut self, query: nosta_relay::NdbQuerySender) -> Self {
        self.state.ndb_query = Some(query);
        self
    }

    pub async fn run(self) -> Result<()> {
        // Public endpoints (no auth required)
        // Note: /:id serves both CID and blossom SHA256 hash lookups
        // The handler differentiates based on hash format (64 char hex = blossom)
        let mut public_routes = Router::new()
            .route("/", get(handlers::serve_root))
            // Blossom endpoints (BUD-01, BUD-02)
            .route("/:id", get(handlers::serve_content_or_blob)
                .head(blossom::head_blob)
                .delete(blossom::delete_blob)
                .options(blossom::cors_preflight))
            .route("/upload", put(blossom::upload_blob)
                .options(blossom::cors_preflight))
            .route("/list/:pubkey", get(blossom::list_blobs)
                .options(blossom::cors_preflight))
            // Nosta API endpoints
            .route("/api/pins", get(handlers::list_pins))
            .route("/api/stats", get(handlers::storage_stats))
            .route("/api/socialgraph", get(handlers::socialgraph_stats))
            .with_state(self.state.clone());

        // Add nostr relay WebSocket endpoint if ndb is configured
        if let Some(relay_state) = self.relay_state {
            let relay_routes = Router::new()
                .route("/", any(ws_handler))
                .with_state(relay_state);
            public_routes = public_routes.merge(relay_routes);
        }

        // Add git smart HTTP routes if git storage is configured
        if let Some(git_storage) = self.git_storage {
            let local_pubkey = self.local_pubkey.unwrap_or_default();
            let git_state = git::GitState { storage: git_storage, local_pubkey };
            let git_routes = Router::new()
                .route("/git/:pubkey/:repo/info/refs", get(git::info_refs))
                .route("/git/:pubkey/:repo/git-upload-pack", post(git::upload_pack))
                .route("/git/:pubkey/:repo/git-receive-pack", post(git::receive_pack))
                .route("/api/git/repos", get(git::list_repos))
                .with_state(git_state);
            public_routes = public_routes.merge(git_routes);
        }

        // Protected endpoints (require auth if enabled)
        let protected_routes = Router::new()
            .route("/upload", post(handlers::upload_file))
            .route("/api/pin/:cid", post(handlers::pin_cid))
            .route("/api/unpin/:cid", post(handlers::unpin_cid))
            .route("/api/gc", post(handlers::garbage_collect))
            .layer(middleware::from_fn_with_state(
                self.state.clone(),
                auth::auth_middleware,
            ))
            .with_state(self.state);

        let app = public_routes
            .merge(protected_routes)
            .layer(DefaultBodyLimit::max(10 * 1024 * 1024 * 1024)); // 10GB limit

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::NostaStore;
    use tempfile::TempDir;
    use std::path::Path;

    #[tokio::test]
    async fn test_server_serve_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Create and upload a test file
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Hello, Nosta!")?;

        let cid = store.upload_file(&test_file)?;

        // Verify we can get it
        let content = store.get_file(&cid)?;
        assert!(content.is_some());
        assert_eq!(content.unwrap(), b"Hello, Nosta!");

        Ok(())
    }

    #[tokio::test]
    async fn test_server_list_pins() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Test")?;

        let cid = store.upload_file(&test_file)?;

        let pins = store.list_pins()?;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], cid);

        Ok(())
    }

    #[tokio::test]
    async fn test_server_bitcoin_pdf() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        let bitcoin_pdf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/bitcoin.pdf");

        if !bitcoin_pdf.exists() {
            return Ok(());
        }

        let cid = store.upload_file(&bitcoin_pdf)?;
        let content = store.get_file(&cid)?;

        assert!(content.is_some());
        let original = std::fs::read(&bitcoin_pdf)?;
        assert_eq!(content.unwrap(), original);

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_protected_endpoints() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Start server with auth
        let server = NostaServer::new(store.clone(), "127.0.0.1:8081".to_string())
            .with_auth("testuser".to_string(), "testpass".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Test protected endpoint without auth - should fail
        let client = reqwest::Client::new();
        let response = client.post("http://127.0.0.1:8081/api/gc").send().await?;
        assert_eq!(response.status(), 401);

        // Test protected endpoint with wrong auth - should fail
        let response = client
            .post("http://127.0.0.1:8081/api/gc")
            .basic_auth("wrong", Some("credentials"))
            .send().await?;
        assert_eq!(response.status(), 401);

        // Test protected endpoint with correct auth - should succeed
        let response = client
            .post("http://127.0.0.1:8081/api/gc")
            .basic_auth("testuser", Some("testpass"))
            .send().await?;
        assert_eq!(response.status(), 200);

        // Test public endpoint without auth - should work
        let response = client.get("http://127.0.0.1:8081/api/stats").send().await?;
        assert_eq!(response.status(), 200);

        Ok(())
    }

    #[tokio::test]
    async fn test_server_without_auth() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Start server without auth
        let server = NostaServer::new(store.clone(), "127.0.0.1:8082".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Test protected endpoint without auth - should work (no auth enabled)
        let client = reqwest::Client::new();
        let response = client.post("http://127.0.0.1:8082/api/gc").send().await?;
        assert_eq!(response.status(), 200);

        Ok(())
    }

    #[tokio::test]
    async fn test_large_file_upload() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Generate a 30MB file
        let large_file = temp_dir.path().join("large.bin");
        let size = 30 * 1024 * 1024; // 30MB
        let mut data = vec![0u8; size];

        // Fill with pseudo-random data
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        std::fs::write(&large_file, &data)?;

        // Upload the file
        let cid = store.upload_file(&large_file)?;
        assert!(!cid.is_empty());

        // Verify retrieval
        let content = store.get_file(&cid)?;
        assert!(content.is_some());
        assert_eq!(content.unwrap().len(), size);

        Ok(())
    }

    #[tokio::test]
    async fn test_range_requests() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Start server
        let server = NostaServer::new(store.clone(), "127.0.0.1:8083".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Create a test file with known content
        let test_file = temp_dir.path().join("test.bin");
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        std::fs::write(&test_file, &data)?;

        // Upload the file
        let cid = store.upload_file(&test_file)?;

        // Verify the file is accessible
        assert!(store.get_file(&cid)?.is_some());

        let client = reqwest::Client::new();

        // Test 1: Request first 100 bytes
        let response = client
            .get(&format!("http://127.0.0.1:8083/{}", cid))
            .header("Range", "bytes=0-99")
            .send()
            .await?;

        assert_eq!(response.status(), 206); // Partial Content
        let content = response.bytes().await?;
        assert_eq!(content.len(), 100);
        assert_eq!(&content[..], &data[0..100]);

        // Test 2: Request middle bytes
        let response = client
            .get(&format!("http://127.0.0.1:8083/{}", cid))
            .header("Range", "bytes=5000-5099")
            .send()
            .await?;

        assert_eq!(response.status(), 206);
        let content = response.bytes().await?;
        assert_eq!(content.len(), 100);
        assert_eq!(&content[..], &data[5000..5100]);

        // Test 3: Request last 100 bytes (open-ended range)
        let response = client
            .get(&format!("http://127.0.0.1:8083/{}", cid))
            .header("Range", "bytes=9900-")
            .send()
            .await?;

        assert_eq!(response.status(), 206);
        let content = response.bytes().await?;
        assert_eq!(content.len(), 100);
        assert_eq!(&content[..], &data[9900..]);

        // Test 4: Request beyond file size (should return 416)
        let response = client
            .get(&format!("http://127.0.0.1:8083/{}", cid))
            .header("Range", "bytes=20000-20099")
            .send()
            .await?;

        assert_eq!(response.status(), 416); // Range Not Satisfiable

        // Test 5: Full file without range (should still work)
        let response = client
            .get(&format!("http://127.0.0.1:8083/{}", cid))
            .send()
            .await?;

        assert_eq!(response.status(), 200);
        let content = response.bytes().await?;
        assert_eq!(content.len(), 10000);
        assert_eq!(&content[..], &data[..]);

        Ok(())
    }

    #[tokio::test]
    async fn test_range_requests_large_chunked_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Start server
        let server = NostaServer::new(store.clone(), "127.0.0.1:8084".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Create a large file that will be chunked (15MB > 2MB chunk size)
        let size = 15 * 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let large_file = temp_dir.path().join("large.bin");
        std::fs::write(&large_file, &data)?;

        // Upload using streaming to ensure chunking
        use std::io::Cursor;
        let cid = store.upload_file_stream(
            Cursor::new(data.clone()),
            "large.bin",
            |_| {}
        )?;

        let client = reqwest::Client::new();

        // Request only first 1KB - should only read first chunk, not all 15MB
        let response = client
            .get(&format!("http://127.0.0.1:8084/{}", cid))
            .header("Range", "bytes=0-1023")
            .send()
            .await?;

        assert_eq!(response.status(), 206);
        let content = response.bytes().await?;
        assert_eq!(content.len(), 1024);
        assert_eq!(&content[..], &data[0..1024]);

        // Request from middle of file (chunk boundary crossing)
        let mid = 5 * 1024 * 1024; // 5MB into file
        let response = client
            .get(&format!("http://127.0.0.1:8084/{}", cid))
            .header("Range", format!("bytes={}-{}", mid, mid + 2047))
            .send()
            .await?;

        assert_eq!(response.status(), 206);
        let content = response.bytes().await?;
        assert_eq!(content.len(), 2048);
        assert_eq!(&content[..], &data[mid..mid + 2048]);

        Ok(())
    }

    #[tokio::test]
    async fn test_blossom_sha256_lookup() -> Result<()> {
        use sha2::{Sha256, Digest};

        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Start server
        let server = NostaServer::new(store.clone(), "127.0.0.1:8085".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Create a test file with known content
        let test_content = b"Hello, Blossom!";
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, test_content)?;

        // Compute SHA256
        let mut hasher = Sha256::new();
        hasher.update(test_content);
        let sha256_hex = hex::encode(hasher.finalize());

        // Upload the file
        let _cid = store.upload_file(&test_file)?;

        let client = reqwest::Client::new();

        // Test 1: Retrieve by SHA256 hash
        let response = client
            .get(&format!("http://127.0.0.1:8085/{}", sha256_hex))
            .send()
            .await?;

        assert_eq!(response.status(), 200);
        // Check CORS header
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        let content = response.bytes().await?;
        assert_eq!(&content[..], test_content);

        // Test 2: Retrieve with extension (blossom style)
        let response = client
            .get(&format!("http://127.0.0.1:8085/{}.txt", sha256_hex))
            .send()
            .await?;

        assert_eq!(response.status(), 200);
        let content = response.bytes().await?;
        assert_eq!(&content[..], test_content);

        // Test 3: Non-existent hash returns 404
        let fake_hash = "0".repeat(64);
        let response = client
            .get(&format!("http://127.0.0.1:8085/{}", fake_hash))
            .send()
            .await?;

        assert_eq!(response.status(), 404);
        // Check CORS header on 404 too
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );

        // Test 4: Uppercase hash works (normalized to lowercase)
        let response = client
            .get(&format!("http://127.0.0.1:8085/{}", sha256_hex.to_uppercase()))
            .send()
            .await?;

        assert_eq!(response.status(), 200);

        Ok(())
    }

    #[tokio::test]
    async fn test_blossom_head_endpoint() -> Result<()> {
        use sha2::{Sha256, Digest};

        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Start server
        let server = NostaServer::new(store.clone(), "127.0.0.1:8086".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let test_content = b"Test content for HEAD";
        let test_file = temp_dir.path().join("head_test.bin");
        std::fs::write(&test_file, test_content)?;

        // Compute SHA256
        let mut hasher = Sha256::new();
        hasher.update(test_content);
        let sha256_hex = hex::encode(hasher.finalize());

        // Upload
        let _cid = store.upload_file(&test_file)?;

        let client = reqwest::Client::new();

        // HEAD request for existing blob
        let response = client
            .head(&format!("http://127.0.0.1:8086/{}", sha256_hex))
            .send()
            .await?;

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        assert!(response.headers().get("content-length").is_some());
        assert!(response.headers().get("content-type").is_some());

        // HEAD for non-existent blob
        let fake_hash = "1".repeat(64);
        let response = client
            .head(&format!("http://127.0.0.1:8086/{}", fake_hash))
            .send()
            .await?;

        assert_eq!(response.status(), 404);

        Ok(())
    }

    #[tokio::test]
    async fn test_blossom_cors_preflight() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        let server = NostaServer::new(store.clone(), "127.0.0.1:8087".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let client = reqwest::Client::new();

        // OPTIONS preflight for upload
        let response = client
            .request(reqwest::Method::OPTIONS, "http://127.0.0.1:8087/upload")
            .send()
            .await?;

        assert_eq!(response.status(), 204);
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        assert!(response
            .headers()
            .get("access-control-allow-methods")
            .is_some());
        assert!(response
            .headers()
            .get("access-control-allow-headers")
            .is_some());

        // OPTIONS preflight for blob endpoint
        let sha256_hex = "a".repeat(64);
        let response = client
            .request(
                reqwest::Method::OPTIONS,
                &format!("http://127.0.0.1:8087/{}", sha256_hex),
            )
            .send()
            .await?;

        assert_eq!(response.status(), 204);

        Ok(())
    }

    #[tokio::test]
    async fn test_blossom_list_endpoint() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        let server = NostaServer::new(store.clone(), "127.0.0.1:8088".to_string());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let client = reqwest::Client::new();

        // List for a pubkey with no blobs - should return empty array
        let fake_pubkey = "b".repeat(64);
        let response = client
            .get(&format!("http://127.0.0.1:8088/list/{}", fake_pubkey))
            .send()
            .await?;

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );

        let body = response.text().await?;
        let blobs: Vec<serde_json::Value> = serde_json::from_str(&body)?;
        assert!(blobs.is_empty());

        // Invalid pubkey format
        let response = client
            .get("http://127.0.0.1:8088/list/invalid")
            .send()
            .await?;

        assert_eq!(response.status(), 400);

        Ok(())
    }

    #[tokio::test]
    async fn test_socialgraph_stats_endpoint() -> Result<()> {
        use nosta_relay::{spawn_relay_thread, RelayConfig};

        let temp_dir = TempDir::new()?;
        let store = Arc::new(NostaStore::new(temp_dir.path().join("db"))?);

        // Initialize nostrdb
        let nostrdb_path = temp_dir.path().join("nostrdb");
        let ndb = crate::init_nostrdb_at(&nostrdb_path)?;

        // Set a root pubkey
        let root_pubkey = [1u8; 32];
        nostrdb::socialgraph::set_root(&ndb, &root_pubkey);

        // Start relay thread with root pubkey
        let relay_config = RelayConfig {
            relays: vec![], // No actual relays for test
            authors: vec![],
            kinds: vec![],
            root_pubkey: Some(root_pubkey),
            crawl_seeds: vec![],
            crawl_depth: 0,
        };
        let relay_handle = spawn_relay_thread(ndb.clone(), relay_config);

        // Start server with ndb query sender
        let server = NostaServer::new(store.clone(), "127.0.0.1:8089".to_string())
            .with_ndb(ndb)
            .with_ndb_query(relay_handle.query.clone());

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        let client = reqwest::Client::new();

        // Test socialgraph endpoint
        let response = client
            .get("http://127.0.0.1:8089/api/socialgraph")
            .send()
            .await?;

        assert_eq!(response.status(), 200);

        let body: serde_json::Value = response.json().await?;

        // Should have stats fields (values may be 0 since no events ingested)
        assert!(body.get("following_count").is_some());
        assert!(body.get("followers_count").is_some());
        assert!(body.get("follow_distance").is_some());

        // Root user should have distance 0
        assert_eq!(body["follow_distance"], 0);

        // Shutdown relay thread
        relay_handle.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }
}

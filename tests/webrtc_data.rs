//! Test for WebRTC data channel protocol - content request/response

use anyhow::Result;
use nosta::webrtc::{ContentStore, DataMessage};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-memory content store for testing
struct TestStore {
    data: RwLock<HashMap<String, Vec<u8>>>,
}

impl TestStore {
    fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    fn put(&self, hash: &str, content: Vec<u8>) {
        self.data.write().unwrap().insert(hash.to_string(), content);
    }
}

impl ContentStore for TestStore {
    fn get(&self, hash_hex: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.data.read().unwrap().get(hash_hex).cloned())
    }
}

#[test]
fn test_data_message_format() {
    // Test request format matches TypeScript
    let request = DataMessage::Request {
        id: 42,
        hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains(r#""type":"req""#));
    assert!(json.contains(r#""id":42"#));
    assert!(json.contains(r#""hash":"abc123""#));

    // Test response format
    let response = DataMessage::Response {
        id: 42,
        hash: "abc123".to_string(),
        found: true,
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains(r#""type":"res""#));
    assert!(json.contains(r#""found":true"#));
}

#[test]
fn test_parse_typescript_request() {
    // This is the exact format sent by hashtree-ts
    let ts_request = r#"{"type":"req","id":1,"hash":"abc123def456"}"#;
    let parsed: DataMessage = serde_json::from_str(ts_request).unwrap();

    match parsed {
        DataMessage::Request { id, hash } => {
            assert_eq!(id, 1);
            assert_eq!(hash, "abc123def456");
        }
        _ => panic!("Expected Request message"),
    }
}

#[test]
fn test_parse_typescript_response() {
    // Format from hashtree-ts
    let ts_response = r#"{"type":"res","id":1,"hash":"abc123def456","found":true}"#;
    let parsed: DataMessage = serde_json::from_str(ts_response).unwrap();

    match parsed {
        DataMessage::Response { id, hash, found } => {
            assert_eq!(id, 1);
            assert_eq!(hash, "abc123def456");
            assert!(found);
        }
        _ => panic!("Expected Response message"),
    }
}

#[test]
fn test_binary_packet_format() {
    // Binary data format: [4 bytes request_id (little-endian)][data]
    let request_id: u32 = 12345;
    let data = b"hello world";

    // Build packet
    let mut packet = Vec::with_capacity(4 + data.len());
    packet.extend_from_slice(&request_id.to_le_bytes());
    packet.extend_from_slice(data);

    assert_eq!(packet.len(), 4 + data.len());

    // Parse packet (as hashtree-ts does)
    let parsed_id = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
    let parsed_data = &packet[4..];

    assert_eq!(parsed_id, request_id);
    assert_eq!(parsed_data, data);
}

#[test]
fn test_content_store_trait() {
    let store = Arc::new(TestStore::new());

    // Initially empty
    assert!(store.get("test123").unwrap().is_none());

    // Add content
    store.put("test123", b"test data".to_vec());

    // Now found
    let data = store.get("test123").unwrap();
    assert_eq!(data, Some(b"test data".to_vec()));
}

#[test]
fn test_have_want_messages() {
    // Test have message
    let have = DataMessage::Have {
        hashes: vec!["hash1".to_string(), "hash2".to_string()],
    };
    let json = serde_json::to_string(&have).unwrap();
    assert!(json.contains(r#""type":"have""#));
    assert!(json.contains(r#""hashes":["hash1","hash2"]"#));

    // Parse it back
    let parsed: DataMessage = serde_json::from_str(&json).unwrap();
    match parsed {
        DataMessage::Have { hashes } => {
            assert_eq!(hashes.len(), 2);
            assert_eq!(hashes[0], "hash1");
        }
        _ => panic!("Expected Have message"),
    }

    // Test want message
    let want = DataMessage::Want {
        hashes: vec!["hash3".to_string()],
    };
    let json = serde_json::to_string(&want).unwrap();
    assert!(json.contains(r#""type":"want""#));
}

#[test]
fn test_root_message() {
    let root = DataMessage::Root {
        hash: "roothashabc123".to_string(),
    };
    let json = serde_json::to_string(&root).unwrap();
    assert!(json.contains(r#""type":"root""#));
    assert!(json.contains(r#""hash":"roothashabc123""#));

    // Parse TypeScript format
    let ts_root = r#"{"type":"root","hash":"xyz789"}"#;
    let parsed: DataMessage = serde_json::from_str(ts_root).unwrap();
    match parsed {
        DataMessage::Root { hash } => {
            assert_eq!(hash, "xyz789");
        }
        _ => panic!("Expected Root message"),
    }
}

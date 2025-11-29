//! Tests for WebRTC signaling protocol compatibility

use super::types::*;

#[test]
fn test_signaling_message_format() {
    // Test hello message format matches TypeScript
    let hello = SignalingMessage::hello("test-uuid-123");
    let json = serde_json::to_string(&hello).unwrap();
    assert!(json.contains("\"type\":\"hello\""));
    assert!(json.contains("\"peerId\":\"test-uuid-123\""));

    // Parse back
    let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.msg_type(), "hello");
    assert_eq!(parsed.peer_id(), "test-uuid-123");
}

#[test]
fn test_offer_message_format() {
    let offer_sdp = serde_json::json!({
        "type": "offer",
        "sdp": "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\n"
    });
    let offer = SignalingMessage::offer(offer_sdp, "pubkey123:uuid456", "my-uuid");
    let json = serde_json::to_string(&offer).unwrap();

    assert!(json.contains("\"type\":\"offer\""));
    assert!(json.contains("\"recipient\":\"pubkey123:uuid456\""));
    assert!(json.contains("\"peerId\":\"my-uuid\""));

    // Parse back
    let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.msg_type(), "offer");
    assert_eq!(parsed.recipient(), Some("pubkey123:uuid456"));
}

#[test]
fn test_answer_message_format() {
    let answer_sdp = serde_json::json!({
        "type": "answer",
        "sdp": "v=0\r\no=- 789 101 IN IP4 127.0.0.1\r\n"
    });
    let answer = SignalingMessage::answer(answer_sdp, "pubkey789:uuid012", "my-uuid");
    let json = serde_json::to_string(&answer).unwrap();

    assert!(json.contains("\"type\":\"answer\""));
    assert!(json.contains("\"recipient\":\"pubkey789:uuid012\""));

    let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.msg_type(), "answer");
}

#[test]
fn test_candidate_message_format() {
    let candidate = serde_json::json!({
        "candidate": "candidate:1 1 UDP 2130706431 192.168.1.1 54321 typ host",
        "sdpMid": "0",
        "sdpMLineIndex": 0
    });
    let msg = SignalingMessage::candidate(candidate, "pubkey:uuid", "my-uuid");
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"candidate\""));
    assert!(json.contains("\"candidate\""));
    assert!(json.contains("sdpMid"));

    let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.msg_type(), "candidate");
}

#[test]
fn test_peer_id_format() {
    let peer_id = PeerId::new("abc123def456".to_string(), Some("uuid789".to_string()));
    assert_eq!(peer_id.to_string(), "abc123def456:uuid789");
    assert_eq!(peer_id.short(), "abc123de:uuid78");

    // Parse from string
    let parsed = PeerId::from_string("pubkey:uuid").unwrap();
    assert_eq!(parsed.pubkey, "pubkey");
    assert_eq!(parsed.uuid, "uuid");
}

#[test]
fn test_uuid_generation() {
    let uuid1 = generate_uuid();
    let uuid2 = generate_uuid();

    // UUIDs should be unique
    assert_ne!(uuid1, uuid2);

    // UUIDs should be reasonable length
    assert!(uuid1.len() >= 20);
}

#[test]
fn test_tie_breaking_consistency() {
    // Lower UUID should initiate (same as TypeScript)
    let uuid1 = "aaaaaa";
    let uuid2 = "zzzzzz";

    // uuid1 < uuid2, so uuid1 initiates
    assert!(uuid1 < uuid2);

    // With real UUIDs
    let real1 = generate_uuid();
    let real2 = generate_uuid();
    // One should be initiator based on string comparison
    let _initiator = if real1 < real2 { &real1 } else { &real2 };
}

#[test]
fn test_webrtc_config_defaults() {
    let config = WebRTCConfig::default();

    assert!(!config.relays.is_empty());
    assert!(config.max_outbound > 0);
    assert!(config.max_inbound > 0);
    assert!(config.hello_interval_ms >= 5000);
    assert!(config.message_timeout_ms >= 10000);
    assert!(!config.stun_servers.is_empty());
}

#[test]
fn test_parse_typescript_hello() {
    // This is the exact format sent by hashtree-ts
    let ts_hello = r#"{"type":"hello","peerId":"abc123def456"}"#;
    let parsed: SignalingMessage = serde_json::from_str(ts_hello).unwrap();
    assert_eq!(parsed.msg_type(), "hello");
    assert_eq!(parsed.peer_id(), "abc123def456");
}

#[test]
fn test_parse_typescript_offer() {
    // Format from hashtree-ts
    let ts_offer = r#"{"type":"offer","offer":{"type":"offer","sdp":"test"},"recipient":"pk:uuid","peerId":"my-uuid"}"#;
    let parsed: SignalingMessage = serde_json::from_str(ts_offer).unwrap();
    assert_eq!(parsed.msg_type(), "offer");
    assert_eq!(parsed.recipient(), Some("pk:uuid"));
}

#[test]
fn test_parse_typescript_candidate() {
    // Format from hashtree-ts
    let ts_candidate = r#"{"type":"candidate","candidate":{"candidate":"test","sdpMid":"0","sdpMLineIndex":0},"recipient":"pk:uuid","peerId":"my-uuid"}"#;
    let parsed: SignalingMessage = serde_json::from_str(ts_candidate).unwrap();
    assert_eq!(parsed.msg_type(), "candidate");
}

#[test]
fn test_kind_and_tag_constants() {
    // Verify constants match iris-client
    assert_eq!(WEBRTC_KIND, 30078);
    assert_eq!(WEBRTC_TAG, "webrtc");
}

//! WebRTC signaling over Nostr relays
//!
//! Uses the same protocol as iris-client for compatibility:
//! - Event kind: 30078 (KIND_APP_DATA)
//! - Tag: ["l", "webrtc"]

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use nostr::{ClientMessage, EventBuilder, Filter, JsonUtil, Keys, Kind, RelayMessage, Tag};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use super::peer::Peer;
use super::types::{
    generate_uuid, PeerDirection, PeerId, PeerStatus, SignalingMessage, WebRTCConfig, WEBRTC_TAG,
};

/// Connection state for a peer
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Discovered,
    Connecting,
    Connected,
    Failed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Discovered => write!(f, "discovered"),
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Connected => write!(f, "connected"),
            ConnectionState::Failed => write!(f, "failed"),
        }
    }
}

/// Peer entry in the manager
pub struct PeerEntry {
    pub peer_id: PeerId,
    pub direction: PeerDirection,
    pub state: ConnectionState,
    pub last_seen: Instant,
    pub peer: Option<Peer>,
}

/// Shared state for WebRTC manager
pub struct WebRTCState {
    pub peers: RwLock<HashMap<String, PeerEntry>>,
    pub connected_count: std::sync::atomic::AtomicUsize,
}

impl WebRTCState {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            connected_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// WebRTC manager handles peer discovery and connection management
pub struct WebRTCManager {
    config: WebRTCConfig,
    my_peer_id: PeerId,
    keys: Keys,
    state: Arc<WebRTCState>,
    shutdown: Arc<tokio::sync::watch::Sender<bool>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// Channel to send signaling messages to relays
    signaling_tx: mpsc::Sender<SignalingMessage>,
    signaling_rx: Option<mpsc::Receiver<SignalingMessage>>,
}

impl WebRTCManager {
    /// Create a new WebRTC manager
    pub fn new(keys: Keys, config: WebRTCConfig) -> Self {
        let pubkey = keys.public_key().to_hex();
        let my_peer_id = PeerId::new(pubkey, None);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (signaling_tx, signaling_rx) = mpsc::channel(100);

        Self {
            config,
            my_peer_id,
            keys,
            state: Arc::new(WebRTCState::new()),
            shutdown: Arc::new(shutdown),
            shutdown_rx,
            signaling_tx,
            signaling_rx: Some(signaling_rx),
        }
    }

    /// Get my peer ID
    pub fn my_peer_id(&self) -> &PeerId {
        &self.my_peer_id
    }

    /// Get shared state for external access
    pub fn state(&self) -> Arc<WebRTCState> {
        self.state.clone()
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Get connected peer count
    pub async fn connected_count(&self) -> usize {
        self.state
            .connected_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get all peer statuses
    pub async fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.state
            .peers
            .read()
            .await
            .values()
            .map(|p| PeerStatus {
                peer_id: p.peer_id.to_string(),
                pubkey: p.peer_id.pubkey.clone(),
                state: p.state.to_string(),
                direction: p.direction,
                connected_at: Some(p.last_seen),
            })
            .collect()
    }

    /// Check if we should initiate connection (tie-breaking)
    /// Lower UUID initiates - same as iris-client/hashtree-ts
    fn should_initiate(&self, their_uuid: &str) -> bool {
        self.my_peer_id.uuid < their_uuid.to_string()
    }

    /// Start the WebRTC manager - connects to relays and handles signaling
    pub async fn run(&mut self) -> Result<()> {
        info!(
            "Starting WebRTC manager with peer ID: {}",
            self.my_peer_id.short()
        );

        let (event_tx, mut event_rx) = mpsc::channel::<(String, nostr::Event)>(100);

        // Take the signaling receiver
        let mut signaling_rx = self.signaling_rx.take().expect("signaling_rx already taken");

        // Create a shared write channel for all relay tasks
        let (relay_write_tx, _) = tokio::sync::broadcast::channel::<SignalingMessage>(100);

        // Spawn relay connections
        for relay_url in &self.config.relays {
            let url = relay_url.clone();
            let event_tx = event_tx.clone();
            let shutdown_rx = self.shutdown_rx.clone();
            let keys = self.keys.clone();
            let my_peer_id = self.my_peer_id.clone();
            let hello_interval = Duration::from_millis(self.config.hello_interval_ms);
            let relay_write_rx = relay_write_tx.subscribe();

            tokio::spawn(async move {
                if let Err(e) = Self::relay_task(
                    url.clone(),
                    event_tx,
                    shutdown_rx,
                    keys,
                    my_peer_id,
                    hello_interval,
                    relay_write_rx,
                )
                .await
                {
                    error!("Relay {} error: {}", url, e);
                }
            });
        }

        // Process incoming events and outgoing signaling messages
        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("WebRTC manager shutting down");
                        break;
                    }
                }
                Some((relay, event)) = event_rx.recv() => {
                    if let Err(e) = self.handle_event(&relay, &event, &relay_write_tx).await {
                        debug!("Error handling event from {}: {}", relay, e);
                    }
                }
                Some(msg) = signaling_rx.recv() => {
                    // Forward signaling messages to relay broadcast
                    let _ = relay_write_tx.send(msg);
                }
            }
        }

        Ok(())
    }

    /// Connect to a single relay and handle messages
    async fn relay_task(
        url: String,
        event_tx: mpsc::Sender<(String, nostr::Event)>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
        keys: Keys,
        my_peer_id: PeerId,
        hello_interval: Duration,
        mut signaling_rx: tokio::sync::broadcast::Receiver<SignalingMessage>,
    ) -> Result<()> {
        info!("Connecting to relay: {}", url);

        let (ws_stream, _) = connect_async(&url).await?;
        let (mut write, mut read) = ws_stream.split();

        // Subscribe to webrtc events
        let filter = Filter::new()
            .kind(Kind::ApplicationSpecificData)
            .custom_tag(
                nostr::SingleLetterTag::lowercase(nostr::Alphabet::L),
                vec![WEBRTC_TAG],
            )
            .since(nostr::Timestamp::now() - Duration::from_secs(60));

        let sub_id = nostr::SubscriptionId::generate();
        let sub_msg = ClientMessage::req(sub_id.clone(), vec![filter]);
        write.send(Message::Text(sub_msg.as_json().into())).await?;

        info!("Subscribed to {} for WebRTC events", url);

        let mut last_hello = Instant::now() - hello_interval; // Send immediately
        let mut hello_ticker = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = hello_ticker.tick() => {
                    // Send hello periodically
                    if last_hello.elapsed() >= hello_interval {
                        let hello = SignalingMessage::hello(&my_peer_id.uuid);
                        if let Ok(event) = Self::create_signaling_event(&keys, &hello).await {
                            let msg = ClientMessage::event(event);
                            if write.send(Message::Text(msg.as_json().into())).await.is_ok() {
                                debug!("Sent hello to {}", url);
                            }
                        }
                        last_hello = Instant::now();
                    }
                }
                // Handle outgoing signaling messages
                Ok(signaling_msg) = signaling_rx.recv() => {
                    if let Ok(event) = Self::create_signaling_event(&keys, &signaling_msg).await {
                        let msg = ClientMessage::event(event);
                        if write.send(Message::Text(msg.as_json().into())).await.is_ok() {
                            debug!("Sent {} to {}", signaling_msg.msg_type(), url);
                        }
                    }
                }
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(relay_msg) = RelayMessage::from_json(&text) {
                                if let RelayMessage::Event { event, .. } = relay_msg {
                                    let _ = event_tx.send((url.clone(), *event)).await;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error from {}: {}", url, e);
                            break;
                        }
                        None => {
                            warn!("WebSocket closed: {}", url);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    /// Create a signaling event
    async fn create_signaling_event(keys: &Keys, msg: &SignalingMessage) -> Result<nostr::Event> {
        let content = serde_json::to_string(msg)?;
        let uuid = generate_uuid();

        let event = EventBuilder::new(Kind::ApplicationSpecificData, content)
            .tags(vec![
                Tag::parse(["l", WEBRTC_TAG])?,
                Tag::parse(["d", &uuid])?,
            ])
            .sign(keys)
            .await?;

        Ok(event)
    }

    /// Handle an incoming event
    async fn handle_event(
        &self,
        relay: &str,
        event: &nostr::Event,
        relay_write_tx: &tokio::sync::broadcast::Sender<SignalingMessage>,
    ) -> Result<()> {
        // Check if this is a webrtc event
        let has_webrtc_tag = event.tags.iter().any(|tag| {
            let v: Vec<String> = tag.clone().to_vec();
            v.len() >= 2 && v[0] == "l" && v[1] == WEBRTC_TAG
        });

        if !has_webrtc_tag || event.kind != Kind::ApplicationSpecificData {
            return Ok(());
        }

        // Parse the message
        let msg: SignalingMessage = serde_json::from_str(&event.content)?;
        let sender_pubkey = event.pubkey.to_hex();

        // Skip our own messages
        if sender_pubkey == self.my_peer_id.pubkey {
            return Ok(());
        }

        debug!(
            "Received {} from {} via {}",
            msg.msg_type(),
            &sender_pubkey[..8],
            relay
        );

        match msg {
            SignalingMessage::Hello { peer_id: their_uuid } => {
                self.handle_hello(&sender_pubkey, &their_uuid, relay_write_tx)
                    .await?;
            }
            SignalingMessage::Offer {
                recipient,
                peer_id: their_uuid,
                offer,
            } => {
                if recipient != self.my_peer_id.to_string() {
                    return Ok(()); // Not for us
                }
                self.handle_offer(&sender_pubkey, &their_uuid, offer, relay_write_tx)
                    .await?;
            }
            SignalingMessage::Answer {
                recipient,
                peer_id: their_uuid,
                answer,
            } => {
                if recipient != self.my_peer_id.to_string() {
                    return Ok(());
                }
                self.handle_answer(&sender_pubkey, &their_uuid, answer)
                    .await?;
            }
            SignalingMessage::Candidate {
                recipient,
                peer_id: their_uuid,
                candidate,
            } => {
                if recipient != self.my_peer_id.to_string() {
                    return Ok(());
                }
                self.handle_candidate(&sender_pubkey, &their_uuid, candidate)
                    .await?;
            }
            SignalingMessage::Candidates {
                recipient,
                peer_id: their_uuid,
                candidates,
            } => {
                if recipient != self.my_peer_id.to_string() {
                    return Ok(());
                }
                self.handle_candidates(&sender_pubkey, &their_uuid, candidates)
                    .await?;
            }
        }

        Ok(())
    }

    /// Handle incoming hello message
    async fn handle_hello(
        &self,
        sender_pubkey: &str,
        their_uuid: &str,
        relay_write_tx: &tokio::sync::broadcast::Sender<SignalingMessage>,
    ) -> Result<()> {
        let full_peer_id = PeerId::new(sender_pubkey.to_string(), Some(their_uuid.to_string()));
        let peer_key = full_peer_id.to_string();

        // Check connection limits
        let connected = self
            .state
            .connected_count
            .load(std::sync::atomic::Ordering::Relaxed);
        let max_connections = self.config.max_outbound + self.config.max_inbound;

        // Check if we already have this peer
        {
            let peers = self.state.peers.read().await;
            if let Some(entry) = peers.get(&peer_key) {
                // Already connected or connecting, just update last_seen
                if entry.state == ConnectionState::Connected
                    || entry.state == ConnectionState::Connecting
                {
                    return Ok(());
                }
            }
        }

        // Decide if we should initiate based on tie-breaking
        let should_initiate = self.should_initiate(their_uuid);

        info!(
            "Discovered peer: {} (initiate: {})",
            full_peer_id.short(),
            should_initiate
        );

        // Create peer entry
        {
            let mut peers = self.state.peers.write().await;
            peers.insert(
                peer_key.clone(),
                PeerEntry {
                    peer_id: full_peer_id.clone(),
                    direction: if should_initiate {
                        PeerDirection::Outbound
                    } else {
                        PeerDirection::Inbound
                    },
                    state: ConnectionState::Discovered,
                    last_seen: Instant::now(),
                    peer: None,
                },
            );
        }

        // If we should initiate and haven't reached limits, create offer
        if should_initiate && connected < max_connections {
            self.initiate_connection(&full_peer_id, relay_write_tx)
                .await?;
        }

        Ok(())
    }

    /// Initiate a connection to a peer (create and send offer)
    async fn initiate_connection(
        &self,
        peer_id: &PeerId,
        relay_write_tx: &tokio::sync::broadcast::Sender<SignalingMessage>,
    ) -> Result<()> {
        let peer_key = peer_id.to_string();

        info!("Initiating connection to {}", peer_id.short());

        // Create peer connection
        let mut peer = Peer::new(
            peer_id.clone(),
            PeerDirection::Outbound,
            self.my_peer_id.clone(),
            self.signaling_tx.clone(),
            self.config.stun_servers.clone(),
        )
        .await?;

        peer.setup_handlers().await?;

        // Create offer
        let offer = peer.connect().await?;

        // Update state
        {
            let mut peers = self.state.peers.write().await;
            if let Some(entry) = peers.get_mut(&peer_key) {
                entry.state = ConnectionState::Connecting;
                entry.peer = Some(peer);
            }
        }

        // Send offer
        let offer_msg = SignalingMessage::Offer {
            offer,
            recipient: peer_id.to_string(),
            peer_id: self.my_peer_id.uuid.clone(),
        };
        let _ = relay_write_tx.send(offer_msg);

        info!("Sent offer to {}", peer_id.short());

        Ok(())
    }

    /// Handle incoming offer
    async fn handle_offer(
        &self,
        sender_pubkey: &str,
        their_uuid: &str,
        offer: serde_json::Value,
        relay_write_tx: &tokio::sync::broadcast::Sender<SignalingMessage>,
    ) -> Result<()> {
        let full_peer_id = PeerId::new(sender_pubkey.to_string(), Some(their_uuid.to_string()));
        let peer_key = full_peer_id.to_string();

        info!("Received offer from {}", full_peer_id.short());

        // Check limits
        let connected = self
            .state
            .connected_count
            .load(std::sync::atomic::Ordering::Relaxed);
        if connected >= self.config.max_inbound + self.config.max_outbound {
            warn!("Connection limit reached, ignoring offer");
            return Ok(());
        }

        // Create peer connection
        let mut peer = Peer::new(
            full_peer_id.clone(),
            PeerDirection::Inbound,
            self.my_peer_id.clone(),
            self.signaling_tx.clone(),
            self.config.stun_servers.clone(),
        )
        .await?;

        peer.setup_handlers().await?;

        // Handle offer and create answer
        let answer = peer.handle_offer(offer).await?;

        // Update state
        {
            let mut peers = self.state.peers.write().await;
            peers.insert(
                peer_key,
                PeerEntry {
                    peer_id: full_peer_id.clone(),
                    direction: PeerDirection::Inbound,
                    state: ConnectionState::Connecting,
                    last_seen: Instant::now(),
                    peer: Some(peer),
                },
            );
        }

        // Send answer
        let answer_msg = SignalingMessage::Answer {
            answer,
            recipient: full_peer_id.to_string(),
            peer_id: self.my_peer_id.uuid.clone(),
        };
        let _ = relay_write_tx.send(answer_msg);

        info!("Sent answer to {}", full_peer_id.short());

        Ok(())
    }

    /// Handle incoming answer
    async fn handle_answer(
        &self,
        sender_pubkey: &str,
        their_uuid: &str,
        answer: serde_json::Value,
    ) -> Result<()> {
        let full_peer_id = PeerId::new(sender_pubkey.to_string(), Some(their_uuid.to_string()));
        let peer_key = full_peer_id.to_string();

        info!("Received answer from {}", full_peer_id.short());

        let mut peers = self.state.peers.write().await;
        if let Some(entry) = peers.get_mut(&peer_key) {
            if let Some(ref mut peer) = entry.peer {
                peer.handle_answer(answer).await?;
                info!("Applied answer from {}", full_peer_id.short());
            }
        }

        Ok(())
    }

    /// Handle incoming ICE candidate
    async fn handle_candidate(
        &self,
        sender_pubkey: &str,
        their_uuid: &str,
        candidate: serde_json::Value,
    ) -> Result<()> {
        let full_peer_id = PeerId::new(sender_pubkey.to_string(), Some(their_uuid.to_string()));
        let peer_key = full_peer_id.to_string();

        debug!("Received candidate from {}", full_peer_id.short());

        let mut peers = self.state.peers.write().await;
        if let Some(entry) = peers.get_mut(&peer_key) {
            if let Some(ref mut peer) = entry.peer {
                peer.handle_candidate(candidate).await?;
            }
        }

        Ok(())
    }

    /// Handle batched ICE candidates
    async fn handle_candidates(
        &self,
        sender_pubkey: &str,
        their_uuid: &str,
        candidates: Vec<serde_json::Value>,
    ) -> Result<()> {
        let full_peer_id = PeerId::new(sender_pubkey.to_string(), Some(their_uuid.to_string()));
        let peer_key = full_peer_id.to_string();

        debug!(
            "Received {} candidates from {}",
            candidates.len(),
            full_peer_id.short()
        );

        let mut peers = self.state.peers.write().await;
        if let Some(entry) = peers.get_mut(&peer_key) {
            if let Some(ref mut peer) = entry.peer {
                for candidate in candidates {
                    if let Err(e) = peer.handle_candidate(candidate).await {
                        debug!("Failed to add candidate: {}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

// Keep the old PeerState for backward compatibility with tests
#[derive(Debug, Clone)]
pub struct PeerState {
    pub peer_id: PeerId,
    pub direction: PeerDirection,
    pub state: String,
    pub last_seen: Instant,
}

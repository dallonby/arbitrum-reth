//! Low-latency canonical state-diff feed for out-of-process consumers.
//!
//! Version 3 extends the reth-bsc v2 layout with complete account lifecycle
//! changes (code, deletion, and storage clearing) plus the canonical header RLP.
//! The fixed 44-byte `BTLV` envelope and bincode payload encoding are unchanged.
//! The producer queues a frame immediately after a block becomes canonical in
//! Reth's in-memory state, before any MDBX flush.

use std::{
    collections::VecDeque,
    fs,
    io::{self, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{sync_channel, SyncSender, TrySendError},
        Arc,
    },
    thread,
    time::Duration,
};

use alloy_primitives::{keccak256, Address, B256, U256};
use eyre::{bail, eyre, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

pub const LIVE_IPC_MAGIC: [u8; 4] = *b"BTLV";
pub const LIVE_IPC_VERSION: u16 = 3;
pub const LIVE_IPC_HEADER_LEN: usize = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LiveIpcKind {
    CanonicalUpdate = 1,
    Hello = 2,
    Reorg = 3,
    Heartbeat = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveIpcMessage {
    CanonicalUpdate(LiveCanonicalUpdateFrame),
    Hello(LiveHelloFrame),
    Reorg(LiveReorgFrame),
    Heartbeat(LiveHeartbeatFrame),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveCheckpointFrame {
    pub block_number: u64,
    pub block_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveAppStateFrame {
    pub name: String,
    pub redb_path: String,
    pub checkpoint: LiveCheckpointFrame,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveHelloFrame {
    pub protocol_version: u16,
    pub producer: String,
    pub app_states: Vec<LiveAppStateFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveReorgFrame {
    pub old_tip: LiveCheckpointFrame,
    pub revert_to: LiveCheckpointFrame,
    pub new_chain: Vec<LiveCanonicalUpdateFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveHeartbeatFrame {
    pub checkpoint: LiveCheckpointFrame,
    pub unix_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveCanonicalBlockFrame {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas: Option<U256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveChainLogFrame {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
    pub transaction_hash: Option<B256>,
    pub transaction_index: Option<u64>,
    pub log_index: Option<u64>,
}

/// The BSC protocol has chain-specific pool and Venus element types in these
/// positions. Arbitrum always transmits both vectors empty, for which bincode's
/// representation is identical regardless of the Rust element type.
pub type ReservedChainSpecificFrame = ();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveCanonicalUpdateFrame {
    pub block: LiveCanonicalBlockFrame,
    pub logs: Vec<LiveChainLogFrame>,
    pub pool_logs: Option<Vec<LiveChainLogFrame>>,
    pub venus_logs: Option<Vec<LiveChainLogFrame>>,
    pub impacted_accounts: Vec<Address>,
    pub pool_updates: Vec<ReservedChainSpecificFrame>,
    pub venus_updates: Vec<ReservedChainSpecificFrame>,
    pub state_changeset: Vec<LiveAccountChangeFrame>,
    /// Canonical alloy header RLP. This carries every chain-specific header
    /// field needed to construct an exact Arbitrum simulation environment.
    pub header_rlp: Vec<u8>,
    /// Wall-clock instant at which the complete post-execution state became
    /// available for feed encoding. Consumers on the same host can subtract
    /// this from their decode-complete time to measure the entire handoff.
    pub state_ready_unix_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveAccountChangeFrame {
    pub address: Address,
    pub account: LiveAccountInfoChangeFrame,
    /// The account's prior storage must be treated as empty before applying
    /// `slots` (newly created, destroyed, or destroyed-and-recreated account).
    pub storage_cleared: bool,
    /// Changed storage slots as `(slot, post_block_value)`.
    pub slots: Vec<(U256, U256)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveAccountInfoChangeFrame {
    /// Balance, nonce, existence, and code are unchanged in this block.
    Unchanged,
    /// Complete post-block account information.
    Updated {
        balance: U256,
        nonce: u64,
        code_hash: B256,
        /// Raw, unpadded bytecode when the code hash changed to non-empty.
        /// Unchanged code remains available from the anchored canonical state.
        code: Option<Vec<u8>>,
    },
    /// The account does not exist in post-block state.
    Deleted,
}

pub fn encode_live_ipc_message(message: &LiveIpcMessage) -> Result<Vec<u8>> {
    match message {
        LiveIpcMessage::CanonicalUpdate(update) => {
            encode_payload(LiveIpcKind::CanonicalUpdate, update)
        }
        LiveIpcMessage::Hello(hello) => encode_payload(LiveIpcKind::Hello, hello),
        LiveIpcMessage::Reorg(reorg) => encode_payload(LiveIpcKind::Reorg, reorg),
        LiveIpcMessage::Heartbeat(heartbeat) => encode_payload(LiveIpcKind::Heartbeat, heartbeat),
    }
}

fn encode_payload<T>(kind: LiveIpcKind, payload: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let payload = bincode::serialize(payload).map_err(|error| eyre!(error))?;
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| eyre!("live IPC payload too large"))?;
    let payload_hash = keccak256(&payload);

    let mut frame = Vec::with_capacity(LIVE_IPC_HEADER_LEN + payload.len());
    frame.extend_from_slice(&LIVE_IPC_MAGIC);
    frame.extend_from_slice(&LIVE_IPC_VERSION.to_be_bytes());
    frame.extend_from_slice(&(kind as u16).to_be_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(payload_hash.as_slice());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_live_ipc_header(frame: &[u8]) -> Result<(LiveIpcKind, u32, B256)> {
    if frame.len() < LIVE_IPC_HEADER_LEN {
        bail!(
            "live IPC frame too short: got {} bytes, need at least {}",
            frame.len(),
            LIVE_IPC_HEADER_LEN
        );
    }
    if frame[0..4] != LIVE_IPC_MAGIC {
        bail!("live IPC magic mismatch");
    }
    let version = u16::from_be_bytes(frame[4..6].try_into()?);
    if version != LIVE_IPC_VERSION {
        bail!(
            "unsupported live IPC version {}, expected {}",
            version,
            LIVE_IPC_VERSION
        );
    }
    let kind = match u16::from_be_bytes(frame[6..8].try_into()?) {
        1 => LiveIpcKind::CanonicalUpdate,
        2 => LiveIpcKind::Hello,
        3 => LiveIpcKind::Reorg,
        4 => LiveIpcKind::Heartbeat,
        other => bail!("unknown live IPC message kind {other}"),
    };
    let payload_len = u32::from_be_bytes(frame[8..12].try_into()?);
    let payload_hash = B256::from_slice(&frame[12..44]);
    Ok((kind, payload_len, payload_hash))
}

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("live IPC dispatcher queue is full")]
    QueueFull,
    #[error("live IPC dispatcher stopped")]
    DispatcherStopped,
}

/// Non-blocking producer handle. Socket writes happen only on dispatcher and
/// per-client threads; a slow reader cannot block the block producer.
pub struct UdsPublisher {
    sender: SyncSender<Vec<u8>>,
    connected_clients: Arc<AtomicUsize>,
    replay_frames: Arc<AtomicUsize>,
    replay_bytes: Arc<AtomicUsize>,
    capture_without_clients: bool,
}

impl UdsPublisher {
    pub fn bind(
        path: PathBuf,
        queue_capacity: usize,
        client_queue_capacity: usize,
        replay_capacity: usize,
        replay_byte_capacity: usize,
    ) -> Result<Self> {
        prepare_socket_path(&path)?;
        let listener = UnixListener::bind(&path)
            .wrap_err_with(|| format!("binding live IPC UDS {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .wrap_err_with(|| format!("restricting live IPC UDS {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .wrap_err("setting live IPC UDS listener nonblocking")?;

        let hello = encode_live_ipc_message(&LiveIpcMessage::Hello(LiveHelloFrame {
            protocol_version: LIVE_IPC_VERSION,
            producer: "arbitrum-reth-live-ipc".to_string(),
            app_states: Vec::new(),
        }))?;
        let (sender, receiver) = sync_channel(queue_capacity.max(1));
        let connected_clients = Arc::new(AtomicUsize::new(0));
        let dispatcher_clients = Arc::clone(&connected_clients);
        let replay_frames = Arc::new(AtomicUsize::new(0));
        let dispatcher_replay_frames = Arc::clone(&replay_frames);
        let replay_bytes = Arc::new(AtomicUsize::new(0));
        let dispatcher_replay_bytes = Arc::clone(&replay_bytes);
        thread::Builder::new()
            .name("arb-live-ipc-uds".to_string())
            .spawn(move || {
                uds_dispatcher_loop(
                    path,
                    listener,
                    receiver,
                    Arc::from(hello),
                    client_queue_capacity.max(1),
                    replay_capacity,
                    replay_byte_capacity,
                    dispatcher_clients,
                    dispatcher_replay_frames,
                    dispatcher_replay_bytes,
                )
            })
            .wrap_err("spawning live IPC UDS dispatcher")?;

        Ok(Self {
            sender,
            connected_clients,
            replay_frames,
            replay_bytes,
            capture_without_clients: replay_capacity > 0 && replay_byte_capacity > 0,
        })
    }

    #[inline]
    pub fn has_clients(&self) -> bool {
        self.connected_client_count() != 0
    }

    #[inline]
    pub fn connected_client_count(&self) -> usize {
        self.connected_clients.load(Ordering::Acquire)
    }

    #[inline]
    pub fn replay_frame_count(&self) -> usize {
        self.replay_frames.load(Ordering::Acquire)
    }

    #[inline]
    pub fn replay_byte_count(&self) -> usize {
        self.replay_bytes.load(Ordering::Acquire)
    }

    /// Whether the producer should materialize a frame. Replay-enabled feeds
    /// retain frames even with no current reader so a fresh rarbi connection
    /// can bridge the complete in-memory/MDBX persistence gap immediately.
    #[inline]
    pub fn should_capture(&self) -> bool {
        self.capture_without_clients || self.has_clients()
    }

    /// Queue one complete encoded frame without waiting for socket I/O.
    pub fn publish(&self, frame: Vec<u8>) -> std::result::Result<(), PublishError> {
        match self.sender.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(PublishError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(PublishError::DispatcherStopped),
        }
    }
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("creating live IPC UDS directory {}", parent.display()))?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)
                .wrap_err_with(|| format!("removing stale live IPC UDS {}", path.display()))?;
        }
        Ok(_) => bail!(
            "live IPC UDS path {} already exists and is not a socket",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .wrap_err_with(|| format!("checking live IPC UDS path {}", path.display()))
        }
    }
    Ok(())
}

const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

struct ClientWriter {
    id: u64,
    sender: SyncSender<Arc<[u8]>>,
    control: UnixStream,
}

impl ClientWriter {
    fn spawn(
        id: u64,
        stream: UnixStream,
        hello: Arc<[u8]>,
        queue_capacity: usize,
    ) -> io::Result<Self> {
        stream.set_nonblocking(false)?;
        stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT))?;
        let control = stream.try_clone()?;
        let (sender, receiver) = sync_channel::<Arc<[u8]>>(queue_capacity);
        thread::Builder::new()
            .name(format!("arb-live-ipc-client-{id}"))
            .spawn(move || {
                let mut stream = stream;
                if let Err(error) = stream.write_all(&hello) {
                    warn!(target: "live_ipc", client_id = id, %error, "live IPC hello write failed");
                    return;
                }
                while let Ok(frame) = receiver.recv() {
                    if let Err(error) = stream.write_all(&frame) {
                        warn!(target: "live_ipc", client_id = id, %error, "live IPC client write failed; disconnecting");
                        break;
                    }
                }
            })?;
        Ok(Self {
            id,
            sender,
            control,
        })
    }

    fn try_enqueue(&self, frame: Arc<[u8]>) -> bool {
        match self.sender.try_send(frame) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                warn!(target: "live_ipc", client_id = self.id, "live IPC client backlog full; disconnecting so it must resync");
                let _ = self.control.shutdown(Shutdown::Both);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

fn uds_dispatcher_loop(
    path: PathBuf,
    listener: UnixListener,
    receiver: std::sync::mpsc::Receiver<Vec<u8>>,
    hello: Arc<[u8]>,
    client_queue_capacity: usize,
    replay_capacity: usize,
    replay_byte_capacity: usize,
    connected_clients: Arc<AtomicUsize>,
    replay_frame_count: Arc<AtomicUsize>,
    replay_byte_count: Arc<AtomicUsize>,
) {
    let mut clients = Vec::<ClientWriter>::new();
    let mut replay = VecDeque::<Arc<[u8]>>::with_capacity(replay_capacity);
    let mut replay_bytes = 0usize;
    let mut next_client_id = 1u64;

    loop {
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let id = next_client_id;
                    next_client_id = next_client_id.saturating_add(1);
                    match ClientWriter::spawn(id, stream, Arc::clone(&hello), client_queue_capacity)
                    {
                        Ok(client) => {
                            // The writer sends hello before reading this queue.
                            // Queue retained frames oldest-to-newest, then admit
                            // the client before processing another live frame.
                            // If a deliberately tiny per-client queue cannot hold
                            // the full replay window, prefer its newest suffix;
                            // the consumer's anchor/continuity guard decides
                            // whether that suffix is sufficient.
                            let replay_start =
                                replay.len().saturating_sub(client_queue_capacity.max(1));
                            let replay_ok = replay
                                .iter()
                                .skip(replay_start)
                                .all(|frame| client.try_enqueue(Arc::clone(frame)));
                            if replay_ok {
                                let replayed = replay.len() - replay_start;
                                clients.push(client);
                                connected_clients.store(clients.len(), Ordering::Release);
                                info!(target: "live_ipc", client_id = id, clients = clients.len(), replayed, path = %path.display(), "live IPC client connected");
                            }
                        }
                        Err(error) => {
                            warn!(target: "live_ipc", client_id = id, %error, "failed to start live IPC client writer");
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    warn!(target: "live_ipc", %error, "live IPC UDS accept failed");
                    break;
                }
            }
        }

        match receiver.recv_timeout(Duration::from_millis(1)) {
            Ok(frame) => {
                let frame: Arc<[u8]> = frame.into();
                if replay_capacity > 0 && replay_byte_capacity > 0 {
                    replay_bytes = replay_bytes.saturating_add(frame.len());
                    replay.push_back(Arc::clone(&frame));
                    while replay.len() > replay_capacity || replay_bytes > replay_byte_capacity {
                        if let Some(evicted) = replay.pop_front() {
                            replay_bytes = replay_bytes.saturating_sub(evicted.len());
                        } else {
                            break;
                        }
                    }
                }
                replay_frame_count.store(replay.len(), Ordering::Release);
                replay_byte_count.store(replay_bytes, Ordering::Release);
                if clients.is_empty() {
                    debug!(target: "live_ipc", bytes = frame.len(), retained = replay.len(), "retaining live IPC frame with no connected client");
                    continue;
                }
                clients.retain(|client| client.try_enqueue(Arc::clone(&frame)));
                connected_clients.store(clients.len(), Ordering::Release);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    connected_clients.store(0, Ordering::Release);
    replay_frame_count.store(0, Ordering::Release);
    replay_byte_count.store(0, Ordering::Release);
    let _ = fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut header = [0u8; LIVE_IPC_HEADER_LEN];
        stream.read_exact(&mut header).unwrap();
        let (_, payload_len, _) = decode_live_ipc_header(&header).unwrap();
        let mut frame = header.to_vec();
        frame.resize(LIVE_IPC_HEADER_LEN + payload_len as usize, 0);
        stream
            .read_exact(&mut frame[LIVE_IPC_HEADER_LEN..])
            .unwrap();
        frame
    }

    #[test]
    fn publisher_fans_out_hello_and_frame() {
        let path = std::env::temp_dir().join(format!(
            "arb-live-ipc-test-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let publisher = UdsPublisher::bind(path.clone(), 16, 16, 8, 1024 * 1024).unwrap();

        let mut a = UnixStream::connect(&path).unwrap();
        let mut b = UnixStream::connect(&path).unwrap();
        let hello_a = read_frame(&mut a);
        let hello_b = read_frame(&mut b);
        assert_eq!(hello_a, hello_b);
        assert_eq!(
            decode_live_ipc_header(&hello_a).unwrap().0,
            LiveIpcKind::Hello
        );

        let message = LiveIpcMessage::Heartbeat(LiveHeartbeatFrame {
            checkpoint: LiveCheckpointFrame {
                block_number: 7,
                block_hash: B256::repeat_byte(0x42),
            },
            unix_millis: 11,
        });
        let expected = encode_live_ipc_message(&message).unwrap();
        publisher.publish(expected.clone()).unwrap();
        assert_eq!(read_frame(&mut a), expected);
        assert_eq!(read_frame(&mut b), expected);

        drop(publisher);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn publisher_replays_frames_retained_before_connect() {
        let path = std::env::temp_dir().join(format!(
            "arb-live-ipc-replay-test-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let publisher = UdsPublisher::bind(path.clone(), 16, 16, 8, 1024 * 1024).unwrap();
        let expected = encode_live_ipc_message(&LiveIpcMessage::Heartbeat(LiveHeartbeatFrame {
            checkpoint: LiveCheckpointFrame {
                block_number: 9,
                block_hash: B256::repeat_byte(0x99),
            },
            unix_millis: 12,
        }))
        .unwrap();
        publisher.publish(expected.clone()).unwrap();
        std::thread::sleep(Duration::from_millis(20));

        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(
            decode_live_ipc_header(&read_frame(&mut client)).unwrap().0,
            LiveIpcKind::Hello
        );
        assert_eq!(read_frame(&mut client), expected);

        drop(publisher);
        let _ = fs::remove_file(path);
    }
}

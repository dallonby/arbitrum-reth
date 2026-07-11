use clap::{Args, ValueEnum};

use std::{path::PathBuf, sync::OnceLock};

/// State-root implementation used by the block producer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum StateRootAlgorithm {
    /// Reth's parallel storage-root workers and flattened in-memory overlay.
    #[default]
    Parallel,
    /// Canonical single-threaded trie walk. Useful as a diagnostic oracle.
    Serial,
}

/// Arbitrum rollup-specific CLI arguments.
#[derive(Debug, Clone, Default, Args)]
#[command(next_help_heading = "Rollup")]
pub struct RollupArgs {
    /// Enable sequencer mode.
    #[arg(long = "rollup.sequencer", default_value_t = false)]
    pub sequencer: bool,

    /// Skip state-root calculation and validation (experimental fast-node mode).
    ///
    /// Unlike an imported L1 block, a Nitro inbox message does not carry a trusted
    /// state root. Blocks produced in this mode therefore retain their parent's root
    /// as a placeholder and do not have canonical hashes. On ArbOS 40 and later,
    /// the next block writes that non-canonical parent hash into EIP-2935 history,
    /// so execution state also diverges from the canonical chain from block two.
    /// This mode is only suitable for isolated performance experiments;
    /// trie-dependent RPCs are disabled.
    #[arg(long = "engine.skip-state-root-validation", default_value_t = false)]
    pub skip_state_root_validation: bool,

    /// State-root implementation for canonical block production.
    #[arg(
        long = "engine.state-root-algorithm",
        value_enum,
        default_value_t = StateRootAlgorithm::Parallel
    )]
    pub state_root_algorithm: StateRootAlgorithm,

    /// Recompute a diagnostic serial state root every N blocks.
    ///
    /// In canonical parallel mode this cross-checks both algorithms. In fast-node
    /// mode it logs a trie root for the already-divergent fast-mode state; it does
    /// not establish equivalence with a canonical chain. Use a large flush interval
    /// for a bounded diagnostic run from a verified checkpoint.
    /// Zero disables verification.
    #[arg(long = "engine.state-root-verify-every", default_value_t = 0)]
    pub state_root_verify_every: u64,

    /// Publish canonical blocks and their in-memory post-execution state diffs
    /// over the reth-bsc-compatible live IPC Unix socket.
    #[arg(
        long = "bot-live-exex.enabled",
        env = "BOT_LIVE_EXEX_ENABLED",
        default_value_t = false
    )]
    pub live_ipc_enabled: bool,

    /// Unix-domain socket path for the low-latency canonical state-diff feed.
    #[arg(long = "bot-live-exex.uds-path", env = "BOT_LIVE_EXEX_UDS_PATH")]
    pub live_ipc_uds_path: Option<PathBuf>,

    /// Bounded frame queue between block execution and the UDS dispatcher.
    #[arg(
        long = "bot-live-exex.queue-capacity",
        env = "BOT_LIVE_EXEX_QUEUE_CAPACITY",
        default_value_t = 4096
    )]
    pub live_ipc_queue_capacity: usize,

    /// Per-client ordered frame backlog. A client exceeding it is disconnected
    /// so a slow rarbi instance cannot add latency to block execution.
    #[arg(
        long = "bot-live-exex.client-queue-capacity",
        env = "BOT_LIVE_EXEX_CLIENT_QUEUE_CAPACITY",
        default_value_t = 4096
    )]
    pub live_ipc_client_queue_capacity: usize,

    /// Number of recent canonical frames retained for a newly connected or
    /// reconnecting consumer. The default is twice the producer's normal
    /// maximum in-memory window, leaving room for the boundary block while a
    /// pending flush completes.
    #[arg(
        long = "bot-live-exex.replay-capacity",
        env = "BOT_LIVE_EXEX_REPLAY_CAPACITY",
        default_value_t = 2048
    )]
    pub live_ipc_replay_capacity: usize,

    /// Total byte bound for retained replay frames. Both this limit and the
    /// frame-count limit apply; oldest frames are evicted first.
    #[arg(
        long = "bot-live-exex.replay-byte-capacity",
        env = "BOT_LIVE_EXEX_REPLAY_BYTE_CAPACITY",
        default_value_t = 268_435_456
    )]
    pub live_ipc_replay_byte_capacity: usize,
}

static RUNTIME_ARGS: OnceLock<RollupArgs> = OnceLock::new();

/// Installs the process-wide rollup settings before node components launch.
pub fn install_runtime_args(args: RollupArgs) -> Result<(), RollupArgs> {
    RUNTIME_ARGS.set(args)
}

/// Returns the configured process-wide rollup settings.
pub fn runtime_args() -> RollupArgs {
    RUNTIME_ARGS.get().cloned().unwrap_or_default()
}

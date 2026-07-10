//! Block producer implementation.
//!
//! Produces blocks from L1 incoming messages by parsing transactions,
//! executing them against the current state, and persisting the results.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use alloy_consensus::{
    proofs, transaction::SignerRecoverable, Block, BlockBody, BlockHeader, Header, TxReceipt,
    EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::eip2718::Decodable2718;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    EvmFactory,
};
use alloy_primitives::{Address, Bytes, B256, B64, U256};
use alloy_rpc_types_eth::BlockNumberOrTag;
use parking_lot::Mutex;
use reth_chain_state::{
    CanonicalInMemoryState, ExecutedBlock, NewCanonicalChain, StateTrieOverlayManager,
};
use reth_chainspec::ChainSpec;
use reth_evm::ConfigureEvm;
use reth_metrics::{
    metrics::{self, Counter, Gauge, Histogram},
    Metrics,
};
use reth_primitives_traits::{logs_bloom, NodePrimitives, SealedHeader};
use reth_provider::{BlockNumReader, BlockReaderIdExt, HeaderProvider, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{StateProvider, StateProviderBox};
use reth_trie_common::{HashedPostState, TrieInputSorted};
use revm::database::{BundleState, StateBuilder};
use revm_database::states::bundle_state::BundleRetention;
use tracing::{debug, info, warn};

use arb_evm::config::{arbos_version_from_mix_hash, l1_block_number_from_mix_hash, ArbEvmConfig};
use arb_primitives::{
    signed_tx::ArbTransactionSigned, tx_types::ArbInternalTx, ArbPrimitives, ArbReceipt,
};
use arb_rpc::block_producer::{
    BlockProducer, BlockProducerError, BlockProductionInput, ProducedBlock,
};
use arbos::{
    arbos_types::parse_init_message,
    header::{derive_arb_header_info, ArbHeaderInfo},
    internal_tx,
    parse_l2::{parse_l2_transactions, parsed_tx_to_signed, ParsedTransaction},
};

use crate::{
    args::StateRootAlgorithm,
    genesis,
    live_ipc::{
        encode_live_ipc_message, LiveAccountChangeFrame, LiveAccountInfoChangeFrame,
        LiveCanonicalBlockFrame, LiveCanonicalUpdateFrame, LiveChainLogFrame, LiveCheckpointFrame,
        LiveIpcMessage, LiveReorgFrame, UdsPublisher,
    },
};

/// State-root policy fixed for the lifetime of a block producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateRootConfig {
    pub skip_validation: bool,
    pub algorithm: StateRootAlgorithm,
    pub verify_every: u64,
}

impl Default for StateRootConfig {
    fn default() -> Self {
        Self {
            skip_validation: false,
            algorithm: StateRootAlgorithm::Parallel,
            verify_every: 0,
        }
    }
}

/// Trait to access the in-memory canonical state from a provider.
///
/// `BlockchainProvider` has `canonical_in_memory_state()` as an inherent method
/// but it's not exposed via any reth trait. This trait bridges that gap so
/// the block producer can receive the handle generically.
pub trait InMemoryStateAccess {
    type Primitives: NodePrimitives;
    fn canonical_in_memory_state(&self) -> CanonicalInMemoryState<Self::Primitives>;
}

/// Implement `InMemoryStateAccess` for reth's `BlockchainProvider`.
impl<N> InMemoryStateAccess for reth_provider::providers::BlockchainProvider<N>
where
    N: reth_provider::providers::ProviderNodeTypes,
{
    type Primitives = N::Primitives;
    fn canonical_in_memory_state(&self) -> CanonicalInMemoryState<Self::Primitives> {
        self.canonical_in_memory_state()
    }
}

pub const DEFAULT_FLUSH_INTERVAL: u64 = 128;
const DEFAULT_MAX_INFLIGHT: usize = 512;

fn max_inflight() -> usize {
    static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("ARB_RETH_MAX_INFLIGHT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_INFLIGHT)
    })
}

/// Avoid rebuilding the cumulative serial-verification overlay on every block
/// while the canonical root itself uses Reth's parallel overlay manager. The
/// once-per-N verification block still takes the unchanged serial path, which
/// differentially checks this accumulator before it can be trusted further.
fn incremental_trie_accumulation_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("ARB_INCREMENTAL_TRIE_ACCUMULATION")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    })
}

/// Fixed-interval flush scheduler with an EMA of commit latency tracked for
/// observability. The interval is set at construction and does not change.
pub struct FlushScheduler {
    interval: u64,
    ema_commit_latency_ms: u64,
}

impl FlushScheduler {
    pub fn new(interval: u64) -> Self {
        Self {
            interval,
            ema_commit_latency_ms: 0,
        }
    }

    pub fn should_flush(&self, since_last: u64) -> bool {
        since_last >= self.interval
    }

    pub fn observe(&mut self, commit_latency_ms: u64) {
        self.ema_commit_latency_ms = (self.ema_commit_latency_ms * 7 + commit_latency_ms * 3) / 10;
    }

    pub fn current_interval(&self) -> u64 {
        self.interval
    }
}

#[cfg(target_os = "linux")]
fn read_dirty_pages_mb() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Dirty:") {
            let kb: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_dirty_pages_mb() -> Option<u64> {
    None
}

/// Prometheus metrics for block production.
#[derive(Metrics)]
#[metrics(scope = "arb_block_producer")]
struct ArbBlockProducerMetrics {
    /// Number of the latest block produced.
    head_block: Gauge,
    /// Total number of blocks produced.
    blocks_produced_total: Counter,
    /// Total gas processed across all produced blocks.
    gas_processed_total: Counter,
    /// Total transactions included across all produced blocks.
    transactions_processed_total: Counter,
    /// Duration of each block flush to disk (save_blocks + commit).
    flush_commit_duration_seconds: Histogram,
    /// Seconds the producer stalled on backpressure, per occurrence.
    backpressure_stall_seconds: Histogram,
    /// Wall-clock time spent computing a canonical state root.
    state_root_duration_seconds: Histogram,
    /// Number of blocks whose state root was intentionally skipped.
    state_root_skipped_total: Counter,
    /// Number of sampled serial/parallel root cross-checks.
    state_root_verifications_total: Counter,
    /// Number of sampled root cross-check mismatches.
    state_root_verification_failures_total: Counter,
    /// Time spent materializing and encoding an in-memory live IPC frame.
    live_ipc_frame_build_duration_seconds: Histogram,
    /// Frames queued for live IPC dispatch and bounded reconnect replay.
    live_ipc_frames_published_total: Counter,
    /// Frames rejected by the bounded dispatcher queue.
    live_ipc_frames_dropped_total: Counter,
    /// Number of live IPC clients currently connected.
    live_ipc_connected_clients: Gauge,
    /// Canonical/reorg frames retained for reconnect replay.
    live_ipc_replay_frames: Gauge,
    /// Encoded bytes retained for reconnect replay.
    live_ipc_replay_bytes: Gauge,
}

/// Block producer using reth's save_blocks(Full) for persistence.
pub struct ArbBlockProducer<Provider> {
    provider: Provider,
    chain_spec: Arc<ChainSpec>,
    evm_config: ArbEvmConfig,
    in_memory_state: CanonicalInMemoryState<ArbPrimitives>,
    head_block_num: AtomicU64,
    blocks_since_flush: AtomicU64,
    scheduler: Mutex<FlushScheduler>,
    accumulated_trie_input: Mutex<Arc<TrieInputSorted>>,
    flushing_trie_input: Mutex<Option<Arc<TrieInputSorted>>>,
    state_trie_overlays: StateTrieOverlayManager<ArbPrimitives>,
    state_root_config: StateRootConfig,
    pending_flush: AtomicBool,
    produce_lock: tokio::sync::Mutex<()>,
    cached_init: Mutex<Option<arbos::arbos_types::ParsedInitMessage>>,
    /// Finality markers propagated by `nitroexecution_setFinalityData`.
    finality: Mutex<FinalityMarkers>,
    /// External shared slot pushed to on every set_finality update so
    /// the `arb_getValidatedBlock` RPC handler can read it without
    /// holding a strong reference to the producer.
    validated_watcher: Mutex<Option<Arc<parking_lot::RwLock<alloy_primitives::B256>>>>,
    /// Cached coalesced storage overlay for the current in-memory chain.
    /// Extended in place after each block produced; invalidated on flush
    /// or rollback so a stale chain view never feeds an SLOAD.
    cached_overlay: Mutex<Option<CachedOverlay>>,
    cached_prestate: Mutex<Option<CachedPrestate>>,
    /// Optional pre-persistence canonical state-diff publisher for rarbi.
    live_ipc: Option<Arc<UdsPublisher>>,
    metrics: ArbBlockProducerMetrics,
}

#[derive(Debug, Default, Clone)]
struct FinalityMarkers {
    safe: Option<alloy_primitives::B256>,
    finalized: Option<alloy_primitives::B256>,
    validated: Option<alloy_primitives::B256>,
}

struct CachedOverlay {
    parent_hash: B256,
    overlay: Arc<crate::coalesced_state::CoalescedOverlay>,
}

struct CachedPrestate {
    parent_hash: B256,
    contracts: Arc<alloy_primitives::map::B256Map<revm::bytecode::Bytecode>>,
}

impl<Provider> ArbBlockProducer<Provider>
where
    Provider: BlockNumReader,
{
    pub fn new(
        provider: Provider,
        chain_spec: Arc<ChainSpec>,
        evm_config: ArbEvmConfig,
        in_memory_state: CanonicalInMemoryState<ArbPrimitives>,
        flush_interval: u64,
        state_root_config: StateRootConfig,
        live_ipc: Option<Arc<UdsPublisher>>,
    ) -> Self {
        // `last_block_number()` only sees the legacy MDBX canonical-header
        // table. Storage V2 keeps canonical headers in static files, so use
        // the layout-aware best block accessor for the persisted producer
        // anchor.
        let head = provider.best_block_number().unwrap_or(0);
        Self {
            provider,
            chain_spec,
            evm_config,
            in_memory_state,
            head_block_num: AtomicU64::new(head),
            blocks_since_flush: AtomicU64::new(0),
            scheduler: Mutex::new(FlushScheduler::new(flush_interval)),
            accumulated_trie_input: Mutex::new(Arc::new(TrieInputSorted::default())),
            flushing_trie_input: Mutex::new(None),
            state_trie_overlays: StateTrieOverlayManager::default(),
            state_root_config,
            pending_flush: AtomicBool::new(false),
            produce_lock: tokio::sync::Mutex::new(()),
            cached_init: Mutex::new(None),
            finality: Mutex::new(FinalityMarkers::default()),
            validated_watcher: Mutex::new(None),
            cached_overlay: Mutex::new(None),
            cached_prestate: Mutex::new(None),
            live_ipc,
            metrics: ArbBlockProducerMetrics::default(),
        }
    }

    fn get_or_build_overlay(
        &self,
        parent_hash: B256,
        head_state: &reth_chain_state::BlockState<ArbPrimitives>,
    ) -> Arc<crate::coalesced_state::CoalescedOverlay> {
        let mut cache = self.cached_overlay.lock();
        if let Some(c) = cache.as_ref() {
            if c.parent_hash == parent_hash {
                return c.overlay.clone();
            }
        }
        let overlay = Arc::new(crate::coalesced_state::CoalescedOverlay::from_chain(
            head_state,
        ));
        *cache = Some(CachedOverlay {
            parent_hash,
            overlay: overlay.clone(),
        });
        overlay
    }

    /// Extend the post-flush serial-verification accumulator without cloning
    /// its full sorted maps when this producer holds the unique Arc.
    fn extend_accumulated_trie_input(
        &self,
        state: &reth_trie_common::HashedPostStateSorted,
        nodes: &reth_trie_common::updates::TrieUpdatesSorted,
    ) {
        let mut accumulated = self.accumulated_trie_input.lock();
        let input = Arc::make_mut(&mut *accumulated);
        if !state.is_empty() {
            Arc::make_mut(&mut input.state).extend_ref_and_sort(state);
        }
        if !nodes.is_empty() {
            Arc::make_mut(&mut input.nodes).extend_ref_and_sort(nodes);
        }
    }

    fn extend_cached_overlay(&self, new_block_hash: B256, bundle: &BundleState) {
        let mut cache = self.cached_overlay.lock();
        let mut overlay = match cache.take() {
            Some(c) => match Arc::try_unwrap(c.overlay) {
                Ok(o) => o,
                Err(arc) => (*arc).clone(),
            },
            None => crate::coalesced_state::CoalescedOverlay::default(),
        };
        overlay.extend_with_block(bundle);
        *cache = Some(CachedOverlay {
            parent_hash: new_block_hash,
            overlay: Arc::new(overlay),
        });
    }

    fn invalidate_cached_overlay(&self) {
        *self.cached_overlay.lock() = None;
    }

    fn get_or_build_prestate(
        &self,
        parent_hash: B256,
        head_state: Option<&reth_chain_state::BlockState<ArbPrimitives>>,
    ) -> Arc<alloy_primitives::map::B256Map<revm::bytecode::Bytecode>> {
        let mut cache = self.cached_prestate.lock();
        if let Some(c) = cache.as_ref() {
            if c.parent_hash == parent_hash {
                return c.contracts.clone();
            }
        }
        let mut contracts: alloy_primitives::map::B256Map<revm::bytecode::Bytecode> =
            Default::default();
        if let Some(head_state) = head_state {
            for block_state in head_state.chain() {
                let exec_output = &block_state.block().execution_output;
                for (hash, code) in &exec_output.state.contracts {
                    contracts.entry(*hash).or_insert_with(|| code.clone());
                }
            }
        }
        let arc = Arc::new(contracts);
        *cache = Some(CachedPrestate {
            parent_hash,
            contracts: arc.clone(),
        });
        arc
    }

    fn extend_cached_prestate(&self, new_block_hash: B256, bundle: &BundleState) {
        let mut cache = self.cached_prestate.lock();
        let mut contracts = match cache.take() {
            Some(c) => match Arc::try_unwrap(c.contracts) {
                Ok(map) => map,
                Err(arc) => (*arc).clone(),
            },
            None => Default::default(),
        };
        for (hash, code) in &bundle.contracts {
            contracts.entry(*hash).or_insert_with(|| code.clone());
        }
        *cache = Some(CachedPrestate {
            parent_hash: new_block_hash,
            contracts: Arc::new(contracts),
        });
    }

    fn invalidate_cached_prestate(&self) {
        *self.cached_prestate.lock() = None;
    }

    /// Currently-tracked finality markers (for RPC / debugging use).
    pub fn finality_markers(
        &self,
    ) -> (
        Option<alloy_primitives::B256>,
        Option<alloy_primitives::B256>,
        Option<alloy_primitives::B256>,
    ) {
        let f = self.finality.lock();
        (f.safe, f.finalized, f.validated)
    }
}

impl<Provider> ArbBlockProducer<Provider>
where
    Provider: BlockNumReader
        + BlockReaderIdExt
        + HeaderProvider<Header = Header>
        + StateProviderFactory
        + Send
        + Sync
        + 'static,
{
    /// Get the current head block number (includes in-memory buffered blocks).
    fn head_block_number(&self) -> Result<u64, BlockProducerError> {
        let head = self.head_block_num.load(Ordering::SeqCst);
        if head > 0 {
            Ok(head)
        } else {
            self.provider
                .best_block_number()
                .map_err(|e| BlockProducerError::StateAccess(e.to_string()))
        }
    }

    /// Get the parent sealed header for block production.
    fn parent_header(&self, head_num: u64) -> Result<SealedHeader<Header>, BlockProducerError> {
        self.provider
            .sealed_header_by_number_or_tag(BlockNumberOrTag::Number(head_num))
            .map_err(|e| BlockProducerError::StateAccess(e.to_string()))?
            .ok_or_else(|| {
                BlockProducerError::StateAccess(format!("Parent block {head_num} not found"))
            })
    }

    fn drain_completed_flush(&self) -> bool {
        if !self.pending_flush.load(Ordering::SeqCst) {
            return false;
        }
        let Some(result) = crate::launcher::try_flush_result() else {
            return false;
        };
        let persisted_hashes = self
            .in_memory_state
            .head_state()
            .map(|state| {
                state
                    .chain()
                    .filter(|block_state| {
                        block_state.block().recovered_block().number()
                            <= result.last_num_hash.number
                    })
                    .map(|block_state| block_state.block().recovered_block().hash())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.state_trie_overlays.remove_blocks(persisted_hashes);
        self.in_memory_state
            .remove_persisted_blocks(result.last_num_hash);
        if !(self.state_root_config.skip_validation && self.state_root_config.verify_every != 0) {
            *self.flushing_trie_input.lock() = None;
        }
        self.pending_flush.store(false, Ordering::SeqCst);
        self.invalidate_cached_overlay();
        self.invalidate_cached_prestate();
        let commit_latency_ms = result.duration.as_millis() as u64;
        self.metrics
            .flush_commit_duration_seconds
            .record(result.duration.as_secs_f64());
        let flush_interval_current = {
            let mut sched = self.scheduler.lock();
            sched.observe(commit_latency_ms);
            sched.current_interval()
        };
        let dirty_pages_mb = read_dirty_pages_mb().unwrap_or(0);
        let chain_len_unflushed = self
            .in_memory_state
            .head_state()
            .map(|s| s.chain().count())
            .unwrap_or(0) as u64;
        info!(
            target: "block_producer",
            flushed = result.count,
            last_block = result.last_num_hash.number,
            mdbx_commit_latency_ms = commit_latency_ms,
            dirty_pages_mb,
            flush_interval_current,
            chain_len_unflushed,
            "block flush"
        );
        true
    }

    async fn apply_backpressure(&self) {
        let chain_len = self
            .in_memory_state
            .head_state()
            .map(|s| s.chain().count())
            .unwrap_or(0);
        let limit = max_inflight();
        if chain_len <= limit {
            return;
        }
        if !self.pending_flush.load(Ordering::SeqCst) {
            self.start_async_flush();
        }
        let start = std::time::Instant::now();
        let notifier = crate::launcher::flush_notifier();
        loop {
            if let Some(n) = notifier.as_ref() {
                // Register interest before checking, so notifications fired
                // between the check and the await are not missed.
                let notified = n.notified();
                if self.drain_completed_flush() {
                    break;
                }
                let waited = tokio::time::timeout(std::time::Duration::from_secs(30), notified)
                    .await
                    .is_ok();
                if !waited {
                    warn!(
                        target: "block_producer",
                        chain_len,
                        waited_ms = start.elapsed().as_millis() as u64,
                        "Backpressure: flush notification timed out, polling once"
                    );
                }
            } else {
                if self.drain_completed_flush() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        self.metrics
            .backpressure_stall_seconds
            .record(start.elapsed().as_secs_f64());
        warn!(
            target: "block_producer",
            chain_len,
            limit,
            waited_ms = start.elapsed().as_millis() as u64,
            "Backpressure: drained pending flush"
        );
    }

    fn produce_block_with_execution(
        &self,
        input: &BlockProductionInput,
        parsed_txs: Vec<ParsedTransaction>,
    ) -> Result<ProducedBlock, BlockProducerError> {
        self.drain_completed_flush();

        let head_num = self.head_block_number()?;
        let l2_block_number = head_num + 1;
        let parent_header = self.parent_header(head_num)?;

        let timestamp = input.l1_timestamp.max(parent_header.timestamp());
        let time_passed = timestamp.saturating_sub(parent_header.timestamp());

        let parent_mix_hash = parent_header.mix_hash().unwrap_or_default();
        let parent_arbos_version = arbos_version_from_mix_hash(&parent_mix_hash);

        // The StartBlock tx carries the reported value verbatim; the EVM sees
        // the monotonic one.
        let l1_block_number = input.l1_block_number;
        let block_l1_block_number = monotonic_l1_block_number(l1_block_number, &parent_mix_hash);
        let arbos_version = parent_arbos_version; // May upgrade during StartBlock

        // Construct a provisional mix_hash for the EVM environment.
        let send_count = {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&parent_mix_hash.0[0..8]);
            u64::from_be_bytes(buf)
        };
        let provisional_mix_hash =
            compute_mix_hash(send_count, block_l1_block_number, arbos_version);

        // Open state at parent block via block hash.
        let raw_state_provider = self
            .provider
            .state_by_block_hash(parent_header.hash())
            .map_err(|e| BlockProducerError::StateAccess(e.to_string()))?;

        let state_provider: StateProviderBox =
            if let Some(head_state) = self.in_memory_state.state_by_hash(parent_header.hash()) {
                let overlay = self.get_or_build_overlay(parent_header.hash(), &head_state);
                if overlay.is_empty() {
                    raw_state_provider
                } else {
                    crate::coalesced_state::CoalescedStateProvider::new(raw_state_provider, overlay)
                        .boxed()
                }
            } else {
                raw_state_provider
            };

        // Read the L2 baseFee from the parent's committed state.
        let l2_base_fee = {
            let read_slot = |addr: Address, slot: B256| state_provider.storage(addr, slot);
            arbos::header::read_l2_base_fee(&read_slot)
                .map_err(|e| BlockProducerError::Storage(e.to_string()))?
                .or(parent_header.base_fee_per_gas())
        };

        // Build a provisional header for the EVM config.
        let provisional_header = Header {
            parent_hash: parent_header.hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: input.sender,
            state_root: B256::ZERO, // placeholder
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            withdrawals_root: None,
            logs_bloom: Default::default(),
            timestamp,
            mix_hash: provisional_mix_hash,
            nonce: B64::from(input.delayed_messages_read.to_be_bytes()),
            base_fee_per_gas: l2_base_fee,
            number: l2_block_number,
            gas_limit: parent_header.gas_limit(),
            difficulty: U256::from(1),
            gas_used: 0,
            extra_data: Default::default(),
            parent_beacon_block_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            requests_hash: None,
            slot_number: None,
            block_access_list_hash: None,
        };

        let evm_env = self
            .evm_config
            .evm_env(&provisional_header)
            .map_err(|_| BlockProducerError::Execution("evm_env construction failed".into()))?;

        // Collect bytecodes from in-memory blocks that might not be flushed to DB yet.
        // When a Stylus contract is deployed in a recent block and the flush hasn't
        // persisted it yet, the DB's Bytecodes table won't have the code. The
        // State<DB>'s `code_by_hash` with `use_preloaded_bundle` will check the
        // bundle_state.contracts before falling back to the DB, ensuring all
        // bytecodes from recent blocks are available during execution.
        let prestate = {
            let head_state_opt = self.in_memory_state.state_by_hash(parent_header.hash());
            let contracts =
                self.get_or_build_prestate(parent_header.hash(), head_state_opt.as_deref());
            BundleState {
                contracts: (*contracts).clone(),
                ..Default::default()
            }
        };

        let mut db = StateBuilder::new()
            .with_database(StateProviderDatabase::new(state_provider.as_ref()))
            .with_bundle_prestate(prestate)
            .with_bundle_update()
            .build();

        let chain_id = self.chain_spec.chain().id();

        // Apply cached ArbOS Init during block 1.
        // Two cases:
        //   - ArbOS not yet initialized (no chainspec alloc): full init from message.
        //   - ArbOS already initialized (chainspec did it with placeholder L1 base fee): override
        //     the L1 price_per_unit slot with the value from the init message, since chainspec has
        //     no way to know the real value.
        if let Some(init_msg) = self.cached_init.lock().take() {
            if !genesis::is_arbos_initialized(&mut db) {
                // Honor the genesis-declared ArbOS version from the parent
                // header's mix_hash so chain specs that target a higher
                // initial version (e.g. v30 / v50 spec fixtures) get the
                // matching hardfork-equivalent EVM activation rather than
                // booting at the v10 default.
                let initial_version = std::env::var("ARB_INITIAL_ARBOS_VERSION")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or({
                        if parent_arbos_version > 0 {
                            parent_arbos_version
                        } else {
                            genesis::INITIAL_ARBOS_VERSION
                        }
                    });
                info!(
                    target: "block_producer",
                    initial_version,
                    "Applying cached ArbOS Init during block {} execution",
                    l2_block_number
                );
                genesis::initialize_arbos_state(
                    &mut db,
                    &init_msg,
                    chain_id,
                    initial_version,
                    genesis::DEFAULT_CHAIN_OWNER,
                    genesis::ArbOSInit::default(),
                )
                .map_err(|e| BlockProducerError::Execution(e.to_string()))?;
            } else {
                use arbos::{arbos_state::ArbosState, burn::SystemBurner};
                info!(
                    target: "block_producer",
                    initial_l1_base_fee = %init_msg.initial_l1_base_fee,
                    "ArbOS already initialized; overriding L1 price_per_unit from Init message"
                );
                // SAFETY: `state_ptr` points at the local `db` owned by
                // this scope; reads through it are sequential and the
                // `&mut *state_ptr` re-borrows are dropped at each call
                // site before the next one, so the type-level aliasing
                // does not overlap at runtime.
                let state_ptr: *mut _ = &mut db;
                let mut arb_state =
                    ArbosState::open(unsafe { &mut *state_ptr }, SystemBurner::new(None, false))
                        .map_err(|e| BlockProducerError::Execution(e.to_string()))?;
                let _ = arb_state.l1_pricing_state.set_price_per_unit(
                    arb_storage::StateDbBackend::from_mut(unsafe { &mut *state_ptr }),
                    init_msg.initial_l1_base_fee,
                );
                if let Ok(target) = std::env::var("ARB_INITIAL_ARBOS_VERSION") {
                    if let Ok(target_version) = target.parse::<u64>() {
                        let current = arb_state.arbos_version();
                        if target_version > current {
                            if let Err(e) = arb_state.upgrade_arbos_version(
                                arb_storage::StateDbBackend::from_mut(unsafe { &mut *state_ptr }),
                                target_version,
                                true,
                            ) {
                                info!(target: "block_producer", err = ?e, target_version, "ArbOS upgrade via env var failed");
                            } else {
                                info!(
                                    target: "block_producer",
                                    from = current,
                                    to = target_version,
                                    "ArbOS upgraded via ARB_INITIAL_ARBOS_VERSION"
                                );
                            }
                        }
                    }
                }
            }
        }

        let parent_extra = parent_header.extra_data().to_vec();
        let mut exec_extra = parent_extra.clone();
        exec_extra.resize(32, 0);
        exec_extra.extend_from_slice(&input.delayed_messages_read.to_be_bytes());

        let exec_ctx = alloy_evm::eth::EthBlockExecutionCtx {
            tx_count_hint: Some(parsed_txs.len() + 2), // +2 for internal txs
            parent_hash: parent_header.hash(),
            parent_beacon_block_root: None,
            ommers: &[],
            withdrawals: None,
            extra_data: exec_extra.into(),
            slot_number: None,
        };

        // Create the block executor via the factory. A multi-gas inspector is
        // installed so the v60 multi-dimensional pricing backlog is driven by
        // per-opcode resource attribution; it publishes each tx's multi-gas to
        // the shared sink the executor reads.
        let multi_gas_sink = arb_evm::multi_gas::MultiGasSink::default();
        let evm_factory = self.evm_config.block_executor_factory().evm_factory();
        let inspector = arb_evm::multi_gas::MultiGasInspector::with_sink(multi_gas_sink.clone());
        let evm = if arb_evm::multi_gas::sparse_inspector_enabled() {
            evm_factory.create_evm_with_sparse_multigas_inspector(
                &mut db,
                evm_env.clone(),
                inspector,
            )
        } else {
            evm_factory.create_evm_with_inspector(&mut db, evm_env.clone(), inspector)
        };
        let mut executor = self
            .evm_config
            .block_executor_factory()
            .create_arb_executor(evm, exec_ctx, chain_id);
        executor.set_multi_gas_sink(multi_gas_sink);
        executor.arb_ctx.l2_block_number = l2_block_number;
        executor.arb_ctx.l1_block_number = block_l1_block_number;

        // 256-ancestor populate only fires on a cold cache.
        let l2_hash_entries = {
            let mut entries = Vec::new();
            let parent_num = l2_block_number.saturating_sub(1);
            entries.push((parent_num, parent_header.hash()));
            let cache_cold = parent_num > 1
                && self
                    .evm_config
                    .executor_factory
                    .arb_evm_factory()
                    .chain_caches()
                    .l2_block_hashes
                    .lock()
                    .get(&parent_num.saturating_sub(1))
                    .is_none();
            if cache_cold {
                let mut hash = parent_header.parent_hash();
                for i in 2..=256u64 {
                    let Some(n) = l2_block_number.checked_sub(i) else {
                        break;
                    };
                    entries.push((n, hash));
                    match self
                        .provider
                        .sealed_header_by_number_or_tag(BlockNumberOrTag::Number(n))
                    {
                        Ok(Some(h)) => hash = h.parent_hash(),
                        _ => break,
                    }
                }
            }
            entries
        };

        // Apply pre-execution changes (loads ArbOS state, fee accounts, block hashes).
        executor
            .apply_pre_execution_changes()
            .map_err(|e| BlockProducerError::Execution(format!("pre-exec: {e}")))?;

        for (l2_num, hash) in l2_hash_entries {
            executor
                .precompile_ctx
                .block
                .cache_l2_block_hash(l2_num, hash);
        }

        let mut all_txs: Vec<ArbTransactionSigned> = Vec::new();

        // 1. Generate and execute the StartBlock internal tx (always first).
        let l1_base_fee = input.l1_base_fee.unwrap_or(U256::ZERO);
        let start_block_data = internal_tx::encode_start_block(
            l1_base_fee,
            l1_block_number,
            l2_block_number,
            time_passed,
        );

        let start_block_tx = create_internal_tx(chain_id, &start_block_data);
        execute_and_commit_tx(&mut executor, &start_block_tx, "StartBlock")?;
        all_txs.push(start_block_tx);

        // Warm sender caches in parallel; kinds with an embedded `from` are skipped.
        let pre_recovered: Vec<Option<ArbTransactionSigned>> = {
            use rayon::prelude::*;
            parsed_txs
                .par_iter()
                .map(|parsed| match parsed {
                    ParsedTransaction::InternalStartBlock { .. }
                    | ParsedTransaction::BatchPostingReport { .. } => None,
                    other => {
                        let signed = parsed_tx_to_signed(other, chain_id)?;
                        let _ = signed.recover_signer();
                        Some(signed)
                    }
                })
                .collect()
        };

        // 2. Execute parsed user transactions.
        for (idx, parsed) in parsed_txs.iter().enumerate() {
            match parsed {
                ParsedTransaction::InternalStartBlock { .. } => {
                    // StartBlock is handled above, skip.
                    continue;
                }
                ParsedTransaction::BatchPostingReport {
                    batch_timestamp,
                    batch_poster,
                    batch_number,
                    l1_base_fee_estimate,
                    extra_gas,
                    ..
                } => {
                    // Delayed message kind=13 contains a batch posting report.
                    // Encode as V1 or V2 based on parent ArbOS version.
                    let report_data =
                        if parent_arbos_version >= arb_chainspec::arbos_version::ARBOS_VERSION_50 {
                            // V2: pass raw batch data stats + extra_gas.
                            let (length, non_zeros) = input.batch_data_stats.unwrap_or((0, 0));
                            internal_tx::encode_batch_posting_report_v2(
                                *batch_timestamp,
                                *batch_poster,
                                *batch_number,
                                length,
                                non_zeros,
                                *extra_gas,
                                *l1_base_fee_estimate,
                            )
                        } else {
                            // V1: combine legacy gas cost + extra_gas into single field.
                            let legacy_gas = input.batch_gas_cost.unwrap_or(0);
                            let batch_data_gas = legacy_gas.saturating_add(*extra_gas);
                            internal_tx::encode_batch_posting_report(
                                *batch_timestamp,
                                *batch_poster,
                                *batch_number,
                                batch_data_gas,
                                *l1_base_fee_estimate,
                            )
                        };
                    let report_tx = create_internal_tx(chain_id, &report_data);
                    execute_and_commit_tx(&mut executor, &report_tx, "BatchPostingReport")?;
                    all_txs.push(report_tx);
                    continue;
                }
                _ => {}
            }

            let signed_tx = match pre_recovered.get(idx).and_then(|s| s.clone()) {
                Some(tx) => tx,
                None => {
                    debug!(target: "block_producer", ?parsed, "Skipping unparseable transaction");
                    continue;
                }
            };

            let recovered = match signed_tx.clone().try_into_recovered() {
                Ok(r) => r,
                Err(e) => {
                    warn!(target: "block_producer", error = %e, "Failed to recover tx sender, skipping");
                    continue;
                }
            };
            let tx_hash = *signed_tx.tx_hash();
            let (exec_outcome, hostio_records) = arb_rpc::stylus_tracer::with_trace_buffer(|| {
                executor.execute_transaction_without_commit(recovered)
            });
            match exec_outcome {
                Ok(result) => {
                    let _ = executor.commit_transaction(result);
                    all_txs.push(signed_tx);
                    if !hostio_records.is_empty() {
                        arb_rpc::stylus_tracer::cache_trace(tx_hash, hostio_records);
                    }

                    // Drain and execute any scheduled txs (auto-redeems).
                    // After a SubmitRetryable or manual Redeem precompile call,
                    // the executor queues retry txs that must execute in the
                    // same block, immediately after the triggering tx.
                    loop {
                        let scheduled = executor.drain_scheduled_txs();
                        debug!(
                            target: "block_producer",
                            count = scheduled.len(),
                            "Drained scheduled txs"
                        );
                        if scheduled.is_empty() {
                            break;
                        }
                        for encoded in scheduled {
                            let retry_tx: Option<ArbTransactionSigned> =
                                ArbTransactionSigned::decode_2718(&mut &encoded[..]).ok();
                            if let Some(retry_tx) = retry_tx {
                                let retry_signed = retry_tx.clone();
                                let retry_hash = *retry_signed.tx_hash();
                                match retry_tx.try_into_recovered() {
                                    Ok(recovered_retry) => {
                                        let (retry_outcome, retry_records) =
                                            arb_rpc::stylus_tracer::with_trace_buffer(|| {
                                                executor.execute_transaction_without_commit(
                                                    recovered_retry,
                                                )
                                            });
                                        match retry_outcome {
                                            Ok(retry_result) => {
                                                let _ = executor.commit_transaction(retry_result);
                                                all_txs.push(retry_signed);
                                                if !retry_records.is_empty() {
                                                    arb_rpc::stylus_tracer::cache_trace(
                                                        retry_hash,
                                                        retry_records,
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                warn!(
                                                    target: "block_producer",
                                                    error = %e,
                                                    "Auto-redeem tx execution failed"
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            target: "block_producer",
                                            error = %e,
                                            "Failed to recover auto-redeem tx sender"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(ref e) if e.to_string().contains("block gas limit reached") => {
                    break;
                }
                Err(e) => {
                    warn!(target: "block_producer", error = %e, "Transaction execution failed, skipping");
                }
            }
        }

        let zombie_accounts = executor.zombie_accounts().clone();
        let finalise_deleted = executor.finalise_deleted().clone();

        let (_, exec_result) = executor
            .finish()
            .map_err(|e| BlockProducerError::Execution(format!("finish: {e}")))?;

        let receipts: Vec<arb_primitives::ArbReceipt> = exec_result.receipts;

        db.merge_transitions(BundleRetention::Reverts);
        let mut bundle = db.take_bundle();

        augment_bundle_from_cache(&mut bundle, &db.cache, &*state_provider)?;

        // Mark per-tx finalise deletions, skipping zombie accounts.
        let keccak_empty_hash = alloy_primitives::B256::from(alloy_primitives::keccak256([]));
        for addr in &finalise_deleted {
            if zombie_accounts.contains(addr) {
                continue;
            }
            if bundle.state.contains_key(addr) {
                let existed_before = state_provider.basic_account(addr).ok().flatten().is_some();
                if existed_before {
                    // Account was in the trie. Only mark as deleted if it's
                    // still empty — it may have been re-created with non-zero
                    // state (e.g., nonce=1) by a later tx in this block.
                    let still_empty = bundle
                        .state
                        .get(addr)
                        .and_then(|a| a.info.as_ref())
                        .is_none_or(|info| {
                            info.nonce == 0
                                && info.balance.is_zero()
                                && info.code_hash == keccak_empty_hash
                        });
                    if still_empty {
                        if let Some(bundle_acct) = bundle.state.get_mut(addr) {
                            bundle_acct.info = None;
                        }
                    }
                } else {
                    let still_empty = bundle
                        .state
                        .get(addr)
                        .and_then(|a| a.info.as_ref())
                        .is_none_or(|info| {
                            info.nonce == 0
                                && info.balance.is_zero()
                                && info.code_hash == keccak_empty_hash
                        });
                    if still_empty {
                        bundle.state.remove(addr);
                    }
                }
                continue;
            }
            if let Ok(Some(acct)) = state_provider.basic_account(addr) {
                let was_originally_empty = acct.balance.is_zero()
                    && acct.nonce == 0
                    && acct.bytecode_hash.is_none_or(|h| h == keccak_empty_hash);
                if was_originally_empty {
                    continue;
                }
                bundle.state.insert(
                    *addr,
                    revm_database::BundleAccount {
                        info: None, // signals trie deletion
                        original_info: None,
                        storage: Default::default(),
                        status: revm_database::AccountStatus::Changed,
                    },
                );
            }
        }

        filter_unchanged_storage(&mut bundle);
        delete_empty_accounts(&mut bundle, &zombie_accounts, &*state_provider);

        // `with_bundle_prestate` seeds execution with bytecode deployed by
        // unflushed ancestor blocks. `take_bundle` retains that seed in
        // `BundleState::contracts`, even though those contracts did not change
        // in this block. Persisting the unfiltered map makes Storage V2 call
        // `write_bytecodes` for the entire growing prestate once per block —
        // quadratic write amplification across a flush batch. Keep only code
        // whose hash actually changed in this block; the cached prestate below
        // then remains exactly the union of unpersisted deployments.
        let changed_code_hashes = bundle
            .state
            .values()
            .filter(|account| account.is_contract_changed())
            .filter_map(|account| account.info.as_ref().map(|info| info.code_hash))
            .collect::<std::collections::HashSet<_>>();
        bundle
            .contracts
            .retain(|code_hash, _| changed_code_hashes.contains(code_hash));

        let hashed_state =
            HashedPostState::from_bundle_state::<reth_trie_common::KeccakKeyHasher>(bundle.state());

        let block_state_sorted = Arc::new(hashed_state.into_sorted());
        let block_prefix_sets = block_state_sorted.construct_prefix_sets();
        let verify_root = self.state_root_config.verify_every != 0
            && l2_block_number % self.state_root_config.verify_every == 0;
        let root_started = std::time::Instant::now();

        let use_incremental_accumulator = incremental_trie_accumulation_enabled()
            && !self.state_root_config.skip_validation
            && self.state_root_config.algorithm == StateRootAlgorithm::Parallel
            && !verify_root;

        let (state_root, trie_updates) = if use_incremental_accumulator {
            let (root, updates) = crate::launcher::compute_parallel_state_root(
                parent_header.hash(),
                self.state_trie_overlays.clone(),
                Arc::clone(&block_state_sorted),
                block_prefix_sets.clone().freeze(),
            )
            .map_err(|e| BlockProducerError::Execution(format!("parallel state root: {e}")))?;
            let updates = Arc::new(updates.into_sorted());
            self.extend_accumulated_trie_input(&block_state_sorted, &updates);
            (root, updates)
        } else {
            let acc_arc = self.accumulated_trie_input.lock().clone();
            let flushing_arc = self.flushing_trie_input.lock().clone();

            let mut new_acc_state = (*acc_arc.state).clone();
            new_acc_state.extend_ref_and_sort(&block_state_sorted);
            let new_acc_state_arc = Arc::new(new_acc_state);

            let (overlay_state_arc, overlay_nodes_arc) = if let Some(f) = &flushing_arc {
                let mut s = (*f.state).clone();
                s.extend_ref_and_sort(&new_acc_state_arc);
                let mut n = (*f.nodes).clone();
                n.extend_ref_and_sort(&acc_arc.nodes);
                (Arc::new(s), Arc::new(n))
            } else {
                (Arc::clone(&new_acc_state_arc), Arc::clone(&acc_arc.nodes))
            };

            let overlay = Arc::new(TrieInputSorted::new(
                overlay_nodes_arc,
                overlay_state_arc,
                Default::default(),
            ));

            if self.state_root_config.skip_validation {
                self.metrics.state_root_skipped_total.increment(1);
                if verify_root {
                    let verify_prefix_sets = new_acc_state_arc.construct_prefix_sets();
                    let (computed_root, _) = crate::launcher::compute_serial_state_root(
                        Arc::clone(&overlay),
                        verify_prefix_sets,
                    )
                    .map_err(|e| {
                        BlockProducerError::Execution(format!(
                            "diagnostic fast-node state root: {e}"
                        ))
                    })?;
                    self.metrics.state_root_verifications_total.increment(1);
                    info!(
                        target: "block_producer",
                        block_num = l2_block_number,
                        ?computed_root,
                        duration_ms = root_started.elapsed().as_millis() as u64,
                        "Computed trie root for non-canonical fast-mode state"
                    );
                }

                // Keep cumulative hashed state only when sampled verification is
                // requested. This permits a bounded diagnostic run from a verified
                // trie anchor without imposing root work on ordinary fast-node mode.
                *self.accumulated_trie_input.lock() = if self.state_root_config.verify_every != 0 {
                    Arc::new(TrieInputSorted::new(
                        Arc::clone(&acc_arc.nodes),
                        new_acc_state_arc,
                        Default::default(),
                    ))
                } else {
                    Arc::new(TrieInputSorted::default())
                };

                (
                    parent_header.state_root(),
                    Arc::new(reth_trie_common::updates::TrieUpdatesSorted::default()),
                )
            } else {
                let (root, updates) = match self.state_root_config.algorithm {
                    StateRootAlgorithm::Parallel => {
                        let parallel = crate::launcher::compute_parallel_state_root(
                            parent_header.hash(),
                            self.state_trie_overlays.clone(),
                            Arc::clone(&block_state_sorted),
                            block_prefix_sets.clone().freeze(),
                        )
                        .map_err(|e| {
                            BlockProducerError::Execution(format!("parallel state root: {e}"))
                        })?;

                        if verify_root {
                            let serial = crate::launcher::compute_serial_state_root(
                                Arc::clone(&overlay),
                                block_prefix_sets.clone(),
                            )
                            .map_err(|e| {
                                BlockProducerError::Execution(format!(
                                    "serial state-root cross-check: {e}"
                                ))
                            })?;
                            self.metrics.state_root_verifications_total.increment(1);
                            if parallel.0 != serial.0 {
                                self.metrics
                                    .state_root_verification_failures_total
                                    .increment(1);
                                return Err(BlockProducerError::Execution(format!(
                                    "state-root algorithms disagree at block {l2_block_number}: parallel={} serial={}",
                                    parallel.0, serial.0
                                )));
                            }
                            info!(
                                target: "block_producer",
                                block_num = l2_block_number,
                                state_root = ?parallel.0,
                                "Parallel and serial state roots agree"
                            );
                        }
                        parallel
                    }
                    StateRootAlgorithm::Serial => {
                        let serial = crate::launcher::compute_serial_state_root(
                            Arc::clone(&overlay),
                            block_prefix_sets.clone(),
                        )
                        .map_err(|e| {
                            BlockProducerError::Execution(format!("serial state root: {e}"))
                        })?;

                        if verify_root {
                            let parallel = crate::launcher::compute_parallel_state_root(
                                parent_header.hash(),
                                self.state_trie_overlays.clone(),
                                Arc::clone(&block_state_sorted),
                                block_prefix_sets.clone().freeze(),
                            )
                            .map_err(|e| {
                                BlockProducerError::Execution(format!(
                                    "parallel state-root cross-check: {e}"
                                ))
                            })?;
                            self.metrics.state_root_verifications_total.increment(1);
                            if parallel.0 != serial.0 {
                                self.metrics
                                    .state_root_verification_failures_total
                                    .increment(1);
                                return Err(BlockProducerError::Execution(format!(
                                    "state-root algorithms disagree at block {l2_block_number}: serial={} parallel={}",
                                    serial.0, parallel.0
                                )));
                            }
                            info!(
                                target: "block_producer",
                                block_num = l2_block_number,
                                state_root = ?serial.0,
                                "Serial and parallel state roots agree"
                            );
                        }
                        serial
                    }
                };

                let updates = Arc::new(updates.into_sorted());
                let mut new_acc_nodes = (*acc_arc.nodes).clone();
                new_acc_nodes.extend_ref_and_sort(updates.as_ref());
                *self.accumulated_trie_input.lock() = Arc::new(TrieInputSorted::new(
                    Arc::new(new_acc_nodes),
                    new_acc_state_arc,
                    Default::default(),
                ));

                (root, updates)
            }
        };
        if !self.state_root_config.skip_validation || verify_root {
            self.metrics
                .state_root_duration_seconds
                .record(root_started.elapsed().as_secs_f64());
        }

        // Derive header info (send_root, send_count, etc.) from post-execution state.
        let arb_info =
            derive_header_info_from_state(state_provider.as_ref(), &bundle, input.sender)?;

        let final_mix_hash = arb_info
            .as_ref()
            .map(|info| info.compute_mix_hash())
            .unwrap_or(provisional_mix_hash);

        let extra_data: Bytes = arb_info
            .as_ref()
            .map(|info| {
                let mut data = info.send_root.to_vec();
                data.resize(32, 0);
                data.into()
            })
            .unwrap_or_else(|| {
                let mut data = parent_extra.clone();
                data.resize(32, 0);
                data.into()
            });

        let send_root = arb_info
            .as_ref()
            .map(|info| info.send_root)
            .unwrap_or_else(|| {
                if parent_extra.len() >= 32 {
                    B256::from_slice(&parent_extra[..32])
                } else {
                    B256::ZERO
                }
            });

        // Compute receipt-derived fields.
        let gas_used = exec_result.gas_used;
        let logs_bloom_val = logs_bloom(receipts.iter().flat_map(|r| r.logs()));

        let transactions_root =
            proofs::calculate_transaction_root::<ArbTransactionSigned>(&all_txs);
        let receipts_root = proofs::calculate_receipt_root(
            &receipts
                .iter()
                .map(|r| r.with_bloom_ref())
                .collect::<Vec<_>>(),
        );

        let header = Header {
            parent_hash: parent_header.hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: input.sender,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root: None,
            logs_bloom: logs_bloom_val,
            timestamp,
            mix_hash: final_mix_hash,
            nonce: B64::from(input.delayed_messages_read.to_be_bytes()),
            base_fee_per_gas: l2_base_fee,
            number: l2_block_number,
            gas_limit: parent_header.gas_limit(),
            difficulty: U256::from(1),
            gas_used,
            extra_data,
            parent_beacon_block_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            requests_hash: None,
            slot_number: None,
            block_access_list_hash: None,
        };

        let block = Block::<ArbTransactionSigned> {
            header,
            body: BlockBody {
                transactions: all_txs,
                ommers: Default::default(),
                withdrawals: None,
            },
        };

        let sealed = reth_primitives_traits::SealedBlock::seal_slow(block);
        let block_hash = sealed.hash();

        self.extend_cached_overlay(block_hash, &bundle);
        self.extend_cached_prestate(block_hash, &bundle);

        // Materialize the feed frame while the per-block BundleState and receipts
        // are still locally owned. Queue it only after the block has become
        // canonical in Reth's in-memory state below. No MDBX work is involved.
        let live_ipc_frame = self
            .live_ipc
            .as_ref()
            .filter(|publisher| publisher.should_capture())
            .map(|_| {
                let started = std::time::Instant::now();
                let result = encode_live_canonical_update(
                    sealed.header(),
                    block_hash,
                    &sealed.body().transactions,
                    &receipts,
                    &bundle,
                );
                self.metrics
                    .live_ipc_frame_build_duration_seconds
                    .record(started.elapsed().as_secs_f64());
                match result {
                    Ok(frame) => Some(frame),
                    Err(error) => {
                        self.metrics.live_ipc_frames_dropped_total.increment(1);
                        warn!(
                            target: "live_ipc",
                            block_num = l2_block_number,
                            %block_hash,
                            %error,
                            "failed to encode live IPC canonical frame; block production will continue"
                        );
                        None
                    }
                }
            })
            .flatten();

        // Buffer block in memory for batched persistence.
        {
            use alloy_evm::block::BlockExecutionResult;
            use reth_chain_state::ComputedTrieData;
            use reth_execution_types::BlockExecutionOutput;
            use reth_primitives_traits::RecoveredBlock;

            // Storage V2 persists transaction senders in a dedicated static-file segment.
            // Every transaction in this block has already been recovered for execution, so this
            // normally reads the warmed sender cache. Keeping the complete sender vector on the
            // executed block is required for `save_blocks(Full)` to advance that segment in lockstep
            // with transactions; an empty vector advances only its block index and makes startup
            // consistency healing unwind the otherwise-durable blocks.
            let recovered = Arc::new(RecoveredBlock::try_recover_sealed(sealed.clone()).map_err(
                |e| {
                    BlockProducerError::Execution(format!(
                        "sender recovery for produced block {l2_block_number}: {e}"
                    ))
                },
            )?);
            let exec_output = Arc::new(BlockExecutionOutput {
                state: bundle,
                result: BlockExecutionResult {
                    receipts,
                    requests: Default::default(),
                    gas_used,
                    blob_gas_used: 0,
                },
            });
            let computed = ComputedTrieData {
                hashed_state: Arc::clone(&block_state_sorted),
                trie_updates: Arc::clone(&trie_updates),
            };
            let executed = ExecutedBlock::new(recovered, exec_output, computed);

            self.state_trie_overlays.insert_block(executed.clone());
            self.in_memory_state
                .update_chain(NewCanonicalChain::Commit {
                    new: vec![executed],
                });

            let sealed_header = SealedHeader::new(sealed.header().clone(), sealed.hash());
            self.in_memory_state.set_canonical_head(sealed_header);
        }

        if let (Some(publisher), Some(frame)) = (&self.live_ipc, live_ipc_frame) {
            match publisher.publish(frame) {
                Ok(()) => self.metrics.live_ipc_frames_published_total.increment(1),
                Err(error) => {
                    self.metrics.live_ipc_frames_dropped_total.increment(1);
                    warn!(
                        target: "live_ipc",
                        block_num = l2_block_number,
                        %block_hash,
                        %error,
                        "canonical block is in memory but its live IPC frame was not queued; consumers must detect the height/hash gap and resync"
                    );
                }
            }
            self.metrics
                .live_ipc_connected_clients
                .set(publisher.connected_client_count() as f64);
            self.metrics
                .live_ipc_replay_frames
                .set(publisher.replay_frame_count() as f64);
            self.metrics
                .live_ipc_replay_bytes
                .set(publisher.replay_byte_count() as f64);
        }

        self.head_block_num.store(l2_block_number, Ordering::SeqCst);

        let num_txs = sealed.body().transactions.len();
        // Update block producer metrics.
        {
            self.metrics.head_block.set(l2_block_number as f64);
            self.metrics.blocks_produced_total.increment(1);
            self.metrics.gas_processed_total.increment(gas_used);
            self.metrics
                .transactions_processed_total
                .increment(num_txs as u64);
        }

        let since_flush = self.blocks_since_flush.fetch_add(1, Ordering::SeqCst) + 1;
        let should_flush = self.scheduler.lock().should_flush(since_flush);
        if should_flush && !self.pending_flush.load(Ordering::SeqCst) {
            self.start_async_flush();
        }

        info!(
            target: "block_producer",
            block_num = l2_block_number,
            ?block_hash,
            ?send_root,
            ?state_root,
            num_txs,
            gas_used,
            "Produced block"
        );

        Ok(ProducedBlock {
            block_hash,
            send_root,
        })
    }

    /// Start an async (non-blocking) flush to the background persistence thread.
    fn start_async_flush(&self) {
        let mut blocks: Vec<ExecutedBlock<ArbPrimitives>> = Vec::new();
        if let Some(head_state) = self.in_memory_state.head_state() {
            for block_state in head_state.chain() {
                blocks.push(block_state.block().clone());
            }
        }
        blocks.reverse();

        if blocks.is_empty() {
            return;
        }

        let last = blocks.last().unwrap();
        let last_num_hash = alloy_eips::BlockNumHash::new(
            last.recovered_block().number(),
            last.recovered_block().hash(),
        );

        // Double-buffer canonical trie input while the persistence transaction
        // runs. A sampled fast-node verifier deliberately retains its cumulative
        // hashed-state overlay because fast persistence does not advance trie
        // tables; this is intended only for bounded diagnostic runs.
        if !(self.state_root_config.skip_validation && self.state_root_config.verify_every != 0) {
            let current = std::mem::take(&mut *self.accumulated_trie_input.lock());
            *self.flushing_trie_input.lock() = Some(current);
        }

        self.blocks_since_flush.store(0, Ordering::SeqCst);
        self.pending_flush.store(true, Ordering::SeqCst);

        let count = blocks.len();
        crate::launcher::start_flush(crate::launcher::FlushRequest {
            blocks,
            last_num_hash,
        });

        debug!(
            target: "block_producer",
            count,
            last_block = last_num_hash.number,
            "Started async flush"
        );
    }
}

#[async_trait::async_trait]
impl<Provider> BlockProducer for ArbBlockProducer<Provider>
where
    Provider: BlockNumReader
        + BlockReaderIdExt
        + HeaderProvider<Header = Header>
        + StateProviderFactory
        + Send
        + Sync
        + 'static,
{
    fn cache_init_message(&self, l2_msg: &[u8]) -> Result<(), BlockProducerError> {
        let init_msg = parse_init_message(l2_msg)
            .map_err(|e| BlockProducerError::Parse(format!("init message: {e}")))?;

        info!(
            target: "block_producer",
            chain_id = %init_msg.chain_id,
            initial_l1_base_fee = %init_msg.initial_l1_base_fee,
            "Cached Init message params"
        );

        *self.cached_init.lock() = Some(init_msg);
        Ok(())
    }

    async fn produce_block(
        &self,
        msg_idx: u64,
        input: BlockProductionInput,
    ) -> Result<ProducedBlock, BlockProducerError> {
        let _lock = self.produce_lock.lock().await;

        // Validate that this message is the next expected one.
        let head_num = self.head_block_number()?;
        let expected_block = head_num + 1;
        let actual_block = msg_idx;

        if expected_block != actual_block {
            return Err(BlockProducerError::Unexpected(format!(
                "Expected block {expected_block} but got msg_idx {msg_idx} (block {actual_block})"
            )));
        }

        // Parse L2 transactions from the message.
        let chain_id = self.chain_spec.chain().id();

        let parsed_txs = parse_l2_transactions(
            input.kind,
            input.sender,
            &input.l2_msg,
            input.request_id,
            input.l1_base_fee,
            chain_id,
        )
        .unwrap_or_else(|e| {
            warn!(target: "block_producer", error=%e, "Error parsing L2 message, treating as empty");
            vec![]
        });

        debug!(
            target: "block_producer",
            msg_idx,
            kind = input.kind,
            num_txs = parsed_txs.len(),
            "Parsed L1 message"
        );

        self.apply_backpressure().await;
        self.produce_block_with_execution(&input, parsed_txs)
    }

    async fn reset_to_block(&self, target_block_number: u64) -> Result<(), BlockProducerError> {
        let _lock = self.produce_lock.lock().await;
        let current = self.head_block_number()?;
        if target_block_number > current {
            return Err(BlockProducerError::Unexpected(format!(
                "reset target {target_block_number} > current head {current}"
            )));
        }
        if target_block_number == current {
            return Ok(());
        }

        let old_tip_header = self.parent_header(current)?;
        let old_tip = LiveCheckpointFrame {
            block_number: current,
            block_hash: old_tip_header.hash(),
        };

        let header = self
            .provider
            .sealed_header_by_number_or_tag(BlockNumberOrTag::Number(target_block_number))
            .map_err(|e| BlockProducerError::StateAccess(e.to_string()))?
            .ok_or_else(|| {
                BlockProducerError::Unexpected(format!(
                    "reset target block {target_block_number} not found"
                ))
            })?;

        // Drain any in-flight flush before unwinding so disk state is consistent.
        if self.pending_flush.load(Ordering::SeqCst) {
            if let Some(result) = crate::launcher::try_flush_result() {
                self.in_memory_state
                    .remove_persisted_blocks(result.last_num_hash);
                *self.flushing_trie_input.lock() = None;
                self.pending_flush.store(false, Ordering::SeqCst);
            }
        }

        // Walk blocks above target in the in-memory state and gather
        // them as "old" for a reorg. Without them, the canonical head
        // points at the truncated block but consumers still see the
        // stale blocks in memory.
        let mut old_blocks: Vec<reth_chain_state::ExecutedBlock<ArbPrimitives>> = Vec::new();
        for bn in (target_block_number + 1)..=current {
            if let Some(state) = self.in_memory_state.state_by_number(bn) {
                old_blocks.push(state.block());
            }
        }

        // Reorg with no new blocks => pure rollback.
        if !old_blocks.is_empty() {
            self.state_trie_overlays.remove_blocks(
                old_blocks
                    .iter()
                    .map(|block| block.recovered_block().hash()),
            );
            self.in_memory_state
                .update_chain(reth_chain_state::NewCanonicalChain::Reorg {
                    new: Vec::new(),
                    old: old_blocks,
                });
        }

        self.invalidate_cached_overlay();
        self.invalidate_cached_prestate();

        // Anchor the canonical head at the rolled-back block so RPC
        // queries like eth_blockNumber return the correct value.
        self.in_memory_state.set_canonical_head(header.clone());

        // Reset the block producer's counter so the next digestMessage
        // extends from the new head.
        self.head_block_num
            .store(target_block_number, Ordering::SeqCst);

        // Announce the in-memory rollback before the (potentially slower) MDBX
        // unwind. As with canonical updates, transport failure is non-fatal to
        // chain correctness and forces consumers to reconnect/resync.
        if let Some(publisher) = self
            .live_ipc
            .as_ref()
            .filter(|publisher| publisher.should_capture())
        {
            let revert_to = LiveCheckpointFrame {
                block_number: target_block_number,
                block_hash: header.hash(),
            };
            match encode_live_ipc_message(&LiveIpcMessage::Reorg(LiveReorgFrame {
                old_tip,
                revert_to,
                new_chain: Vec::new(),
            })) {
                Ok(frame) => match publisher.publish(frame) {
                    Ok(()) => self.metrics.live_ipc_frames_published_total.increment(1),
                    Err(error) => {
                        self.metrics.live_ipc_frames_dropped_total.increment(1);
                        warn!(target: "live_ipc", target_block_number, %error, "live IPC reorg frame was not queued");
                    }
                },
                Err(error) => {
                    self.metrics.live_ipc_frames_dropped_total.increment(1);
                    warn!(target: "live_ipc", target_block_number, %error, "failed to encode live IPC reorg frame");
                }
            }
            self.metrics
                .live_ipc_connected_clients
                .set(publisher.connected_client_count() as f64);
            self.metrics
                .live_ipc_replay_frames
                .set(publisher.replay_frame_count() as f64);
            self.metrics
                .live_ipc_replay_bytes
                .set(publisher.replay_byte_count() as f64);
        }

        // Also remove persisted blocks above target from disk. The worker
        // thread runs this serially with flushes to avoid races.
        if let Some(rx) = crate::launcher::start_unwind(target_block_number) {
            match rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    return Err(BlockProducerError::Storage(format!(
                        "unwind above {target_block_number}: {e}"
                    )));
                }
                Err(e) => {
                    return Err(BlockProducerError::Storage(format!(
                        "unwind channel closed: {e}"
                    )));
                }
            }
        }

        // Invalidate any trie-input carrying the now-removed blocks.
        *self.accumulated_trie_input.lock() = Arc::new(TrieInputSorted::default());
        *self.flushing_trie_input.lock() = None;

        if self.state_root_config.skip_validation && self.state_root_config.verify_every != 0 {
            warn!(
                target: "block_producer",
                "Fast-node state-root sampling was reset; restart from a verified trie checkpoint before relying on another sampled root"
            );
        }

        info!(
            target: "block_producer",
            target = target_block_number,
            hash = %header.hash(),
            old_count = current - target_block_number,
            "reset head"
        );
        Ok(())
    }

    fn set_finality(
        &self,
        safe: Option<alloy_primitives::B256>,
        finalized: Option<alloy_primitives::B256>,
        validated: Option<alloy_primitives::B256>,
    ) -> Result<(), BlockProducerError> {
        let mut f = self.finality.lock();
        if safe.is_some() {
            f.safe = safe;
        }
        if finalized.is_some() {
            f.finalized = finalized;
        }
        if validated.is_some() {
            f.validated = validated;
        }
        drop(f);

        // Propagate to reth's canonical in-memory state so
        // eth_getBlockByNumber("safe" | "finalized") returns the
        // correct header.
        if let Some(h) = safe {
            if let Ok(Some(sealed)) = self.provider.sealed_header_by_hash(h) {
                self.in_memory_state.set_safe(sealed);
            }
        }
        if let Some(h) = finalized {
            if let Ok(Some(sealed)) = self.provider.sealed_header_by_hash(h) {
                self.in_memory_state.set_finalized(sealed);
            }
        }
        // `validated` is Arbitrum-specific — reth's canonical state
        // exposes only safe/finalized. Push to the external watcher
        // so `arb_getValidatedBlock` RPC returns the latest value.
        if let Some(h) = validated {
            if let Some(w) = self.validated_watcher.lock().as_ref() {
                *w.write() = h;
            }
        }
        Ok(())
    }

    fn attach_validated_watcher(&self, watcher: Arc<parking_lot::RwLock<alloy_primitives::B256>>) {
        *self.validated_watcher.lock() = Some(watcher);
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Encode the versioned canonical frame directly from this block's execution
/// artifacts. This deliberately consumes only references so the same
/// `BundleState` can then move into Reth's in-memory executed block.
fn encode_live_canonical_update(
    header: &Header,
    block_hash: B256,
    transactions: &[ArbTransactionSigned],
    receipts: &[ArbReceipt],
    bundle: &BundleState,
) -> Result<Vec<u8>, BlockProducerError> {
    let mut logs = Vec::new();
    let mut log_index = 0u64;
    for (tx_index, receipt) in receipts.iter().enumerate() {
        let transaction_hash = transactions.get(tx_index).map(|tx| *tx.tx_hash());
        for log in receipt.logs() {
            logs.push(LiveChainLogFrame {
                address: log.address,
                topics: log.topics().to_vec(),
                data: log.data.data.to_vec(),
                transaction_hash,
                transaction_index: Some(tx_index as u64),
                log_index: Some(log_index),
            });
            log_index = log_index.saturating_add(1);
        }
    }

    let mut state_changeset = Vec::new();
    for (address, account) in &bundle.state {
        let mut slots: Vec<(U256, U256)> = account
            .storage
            .iter()
            .filter(|(_, slot)| slot.is_changed())
            .map(|(key, slot)| (*key, slot.present_value))
            .collect();

        let account_change = if account.is_info_changed() {
            match &account.info {
                Some(present) => {
                    let code = if account.is_contract_changed()
                        && present.code_hash != alloy_primitives::KECCAK256_EMPTY
                    {
                        let bytecode = present
                            .code
                            .as_ref()
                            .filter(|code| code.hash_slow() == present.code_hash)
                            .or_else(|| bundle.contracts.get(&present.code_hash))
                            .ok_or_else(|| {
                                BlockProducerError::Execution(format!(
                                    "live IPC changed code {} for {address} is unavailable",
                                    present.code_hash
                                ))
                            })?;
                        Some(bytecode.original_byte_slice().to_vec())
                    } else {
                        None
                    };
                    LiveAccountInfoChangeFrame::Updated {
                        balance: present.balance,
                        nonce: present.nonce,
                        code_hash: present.code_hash,
                        code,
                    }
                }
                None => LiveAccountInfoChangeFrame::Deleted,
            }
        } else {
            LiveAccountInfoChangeFrame::Unchanged
        };

        let storage_cleared = account.status.is_storage_known()
            && (account.is_info_changed() || account.was_destroyed());
        if slots.is_empty()
            && !storage_cleared
            && matches!(&account_change, LiveAccountInfoChangeFrame::Unchanged)
        {
            continue;
        }
        slots.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        state_changeset.push(LiveAccountChangeFrame {
            address: *address,
            account: account_change,
            storage_cleared,
            slots,
        });
    }
    state_changeset.sort_unstable_by(|a, b| a.address.cmp(&b.address));

    let update = LiveCanonicalUpdateFrame {
        block: LiveCanonicalBlockFrame {
            number: header.number,
            hash: block_hash,
            parent_hash: header.parent_hash,
            timestamp: header.timestamp,
            gas_limit: header.gas_limit,
            base_fee_per_gas: header.base_fee_per_gas.map(U256::from),
        },
        logs,
        pool_logs: None,
        venus_logs: None,
        impacted_accounts: Vec::new(),
        pool_updates: Vec::new(),
        venus_updates: Vec::new(),
        state_changeset,
        header_rlp: alloy_rlp::encode(header),
        state_ready_unix_nanos: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX),
    };

    encode_live_ipc_message(&LiveIpcMessage::CanonicalUpdate(update))
        .map_err(|error| BlockProducerError::Execution(format!("encode live IPC update: {error}")))
}

/// Create an internal transaction (type 0x6A).
fn create_internal_tx(chain_id: u64, data: &[u8]) -> ArbTransactionSigned {
    use arb_primitives::signed_tx::ArbTypedTransaction;
    let tx = ArbTypedTransaction::Internal(ArbInternalTx {
        chain_id: U256::from(chain_id),
        data: Bytes::copy_from_slice(data),
    });
    let sig = alloy_primitives::Signature::new(U256::ZERO, U256::ZERO, false);
    ArbTransactionSigned::new_unhashed(tx, sig)
}

/// Execute and commit an internal transaction via the block executor.
fn execute_and_commit_tx<E>(
    executor: &mut E,
    tx: &ArbTransactionSigned,
    label: &str,
) -> Result<(), BlockProducerError>
where
    E: BlockExecutor<Transaction = ArbTransactionSigned>,
{
    let recovered = tx
        .clone()
        .try_into_recovered()
        .map_err(|e| BlockProducerError::Execution(format!("{label} recovery: {e}")))?;

    let result = executor
        .execute_transaction_without_commit(recovered)
        .map_err(|e| BlockProducerError::Execution(format!("{label} execution: {e}")))?;

    let _ = executor.commit_transaction(result);

    Ok(())
}

fn compute_mix_hash(send_count: u64, l1_block_number: u64, arbos_version: u64) -> B256 {
    arbos::header::compute_arbos_mixhash(send_count, l1_block_number, arbos_version, false)
}

/// L1 block number for the `NUMBER` opcode: monotonic, so a reported value
/// below the parent's (recovered from its mix_hash) is clamped up to it.
fn monotonic_l1_block_number(reported: u64, parent_mix_hash: &B256) -> u64 {
    reported.max(l1_block_number_from_mix_hash(parent_mix_hash))
}

/// EIP-161: mark empty non-zombie accounts for trie deletion.
fn delete_empty_accounts(
    bundle: &mut BundleState,
    zombie_accounts: &rustc_hash::FxHashSet<Address>,
    state_provider: &dyn StateProvider,
) {
    let keccak_empty = alloy_primitives::B256::from(alloy_primitives::keccak256([]));
    let mut to_remove = Vec::new();
    for (addr, account) in bundle.state.iter_mut() {
        if let Some(ref info) = account.info {
            let is_empty =
                info.nonce == 0 && info.balance.is_zero() && info.code_hash == keccak_empty;
            if is_empty && !zombie_accounts.contains(addr) {
                let existed_before = state_provider.basic_account(addr).ok().flatten().is_some();
                if existed_before {
                    debug!(
                        target: "block_producer",
                        addr = ?addr,
                        "EIP-161: deleting empty account from state"
                    );
                    account.info = None;
                } else {
                    to_remove.push(*addr);
                }
            }
        }
    }
    for addr in to_remove {
        bundle.state.remove(&addr);
    }
}

/// Remove unchanged storage slots from the bundle.
fn filter_unchanged_storage(bundle: &mut BundleState) {
    for (_addr, account) in bundle.state.iter_mut() {
        account
            .storage
            .retain(|_key, slot| slot.present_value != slot.previous_or_original_value);
    }
}

/// Derive ArbHeaderInfo from post-execution state.
fn derive_header_info_from_state(
    state_provider: &dyn StateProvider,
    bundle_state: &BundleState,
    coinbase: Address,
) -> Result<Option<ArbHeaderInfo>, BlockProducerError> {
    let read_slot = |addr: Address, slot: B256| {
        if let Some(account) = bundle_state.state.get(&addr) {
            let slot_u256 = U256::from_be_bytes(slot.0);
            if let Some(storage_slot) = account.storage.get(&slot_u256) {
                return Ok(Some(storage_slot.present_value));
            }
        }
        state_provider.storage(addr, slot)
    };

    derive_arb_header_info(&read_slot, coinbase)
        .map_err(|e| BlockProducerError::Storage(e.to_string()))
}

/// Augment the bundle with direct cache modifications not captured by EVM transitions.
fn augment_bundle_from_cache(
    bundle: &mut BundleState,
    cache: &revm_database::CacheState,
    state_provider: &dyn StateProvider,
) -> Result<(), BlockProducerError> {
    use revm_database::states::plain_account::StorageSlot;

    for (addr, cache_acct) in &cache.accounts {
        let current_info = cache_acct.account.as_ref().map(|a| a.info.clone());
        let current_storage = cache_acct
            .account
            .as_ref()
            .map(|a| &a.storage)
            .cloned()
            .unwrap_or_default();

        if let Some(bundle_acct) = bundle.state.get_mut(addr) {
            // Update existing bundle entry from cache.
            bundle_acct.info = current_info;

            for (key, value) in &current_storage {
                if let Some(slot) = bundle_acct.storage.get_mut(key) {
                    slot.present_value = *value;
                } else {
                    // Slot written via direct cache modification.
                    let original_value = state_provider
                        .storage(*addr, B256::from(*key))
                        .map_err(|e| BlockProducerError::Storage(e.to_string()))?
                        .unwrap_or(U256::ZERO);
                    if *value != original_value {
                        bundle_acct.storage.insert(
                            *key,
                            StorageSlot {
                                previous_or_original_value: original_value,
                                present_value: *value,
                            },
                        );
                    }
                }
            }
        } else {
            // Account not in bundle — check if modified from original.
            let original = state_provider
                .basic_account(addr)
                .map_err(|e| BlockProducerError::Storage(e.to_string()))?;

            let info_changed = match (&original, &current_info) {
                (None, None) => false,
                (Some(_), None) | (None, Some(_)) => true,
                (Some(orig), Some(curr)) => {
                    orig.balance != curr.balance
                        || orig.nonce != curr.nonce
                        || orig
                            .bytecode_hash
                            .unwrap_or(alloy_primitives::KECCAK256_EMPTY)
                            != curr.code_hash
                }
            };

            let mut storage_changes: alloy_primitives::map::U256Map<StorageSlot> =
                alloy_primitives::map::U256Map::default();
            for (key, value) in &current_storage {
                let original_value = state_provider
                    .storage(*addr, B256::from(*key))
                    .map_err(|e| BlockProducerError::Storage(e.to_string()))?
                    .unwrap_or(U256::ZERO);
                if original_value != *value {
                    storage_changes.insert(
                        *key,
                        StorageSlot {
                            previous_or_original_value: original_value,
                            present_value: *value,
                        },
                    );
                }
            }

            if info_changed || !storage_changes.is_empty() {
                let original_info = original.as_ref().map(|a| revm::state::AccountInfo {
                    balance: a.balance,
                    nonce: a.nonce,
                    code_hash: a.bytecode_hash.unwrap_or(alloy_primitives::KECCAK256_EMPTY),
                    code: None,
                    account_id: None,
                });

                let status = if original.is_some() {
                    revm_database::AccountStatus::Changed
                } else {
                    revm_database::AccountStatus::InMemoryChange
                };

                bundle.state.insert(
                    *addr,
                    revm_database::BundleAccount {
                        info: current_info,
                        original_info,
                        storage: storage_changes,
                        status,
                    },
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbos::header::compute_arbos_mixhash;

    #[test]
    fn l1_block_number_clamps_to_parent() {
        let parent = compute_arbos_mixhash(0, 10_538_022, 51, false);
        // A lower sequencer-reported value is clamped up to the parent's.
        assert_eq!(monotonic_l1_block_number(10_537_967, &parent), 10_538_022);
        // A higher value advances normally.
        assert_eq!(monotonic_l1_block_number(10_538_099, &parent), 10_538_099);
        // Equal stays put.
        assert_eq!(monotonic_l1_block_number(10_538_022, &parent), 10_538_022);
    }
}

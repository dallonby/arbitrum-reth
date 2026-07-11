//! Arbitrum node builder.
//!
//! Provides the node type definition and component builders
//! needed to launch an Arbitrum reth node.

pub mod addons;
pub mod args;
pub mod chainspec;
pub mod coalesced_state;
pub mod consensus;
pub mod engine;
pub mod error;
pub mod genesis;
pub mod launcher;
pub mod live_ipc;
pub mod network;
pub mod payload;
pub mod pool;
pub mod producer;
pub mod validator;

pub use error::{GenesisError, LauncherError};

use std::sync::Arc;

use alloy_consensus::Header;
use arb_payload::ArbEngineTypes;
use arb_primitives::{ArbPrimitives, ArbTransactionSigned};
use arb_rpc::{
    stylus_debug::{StylusDebugHandler, StylusDebugServer},
    ArbApiHandler, ArbApiServer, ArbEthApiBuilder, NitroExecutionApiServer, NitroExecutionHandler,
};
use reth_chain_state::CanonicalInMemoryState;
use reth_chainspec::ChainSpec;
use reth_node_builder::{
    components::{ComponentsBuilder, ConsensusBuilder, ExecutorBuilder},
    rpc::{BasicEngineApiBuilder, BasicEngineValidatorBuilder, RpcAddOns, RpcContext},
    BuilderContext, FullNodeComponents, FullNodeTypes, Node, NodeAdapter, NodeTypes,
};
use reth_provider::{BlockNumReader, BlockReaderIdExt, HeaderProvider, StateProviderFactory};
use reth_storage_api::{CanonChainTracker, EthStorage};

use arb_evm::ArbEvmConfig;

use crate::{
    addons::ArbPayloadValidatorBuilder,
    args::RollupArgs,
    consensus::ArbConsensus,
    network::ArbNetworkBuilder,
    payload::ArbPayloadServiceBuilder,
    pool::ArbPoolBuilder,
    producer::{ArbBlockProducer, InMemoryStateAccess, StateRootConfig},
};

/// Arbitrum RPC add-ons type alias.
pub type ArbAddOns<N> = RpcAddOns<
    N,
    ArbEthApiBuilder,
    ArbPayloadValidatorBuilder,
    BasicEngineApiBuilder<ArbPayloadValidatorBuilder>,
    BasicEngineValidatorBuilder<ArbPayloadValidatorBuilder>,
>;

/// Arbitrum storage type.
pub type ArbStorage = EthStorage<ArbTransactionSigned>;

/// Arbitrum node configuration.
#[derive(Debug, Clone, Default)]
pub struct ArbNode {
    /// Rollup CLI arguments.
    pub args: RollupArgs,
}

impl ArbNode {
    /// Create a new Arbitrum node configuration.
    pub fn new(args: RollupArgs) -> Self {
        Self { args }
    }

    /// Returns a [`ComponentsBuilder`] configured for Arbitrum.
    pub fn components<N>() -> ComponentsBuilder<
        N,
        ArbPoolBuilder,
        ArbPayloadServiceBuilder,
        ArbNetworkBuilder,
        ArbExecutorBuilder,
        ArbConsensusBuilder,
    >
    where
        N: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = ArbPrimitives>>,
    {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(ArbPoolBuilder)
            .executor(ArbExecutorBuilder)
            .payload(ArbPayloadServiceBuilder)
            .network(ArbNetworkBuilder)
            .consensus(ArbConsensusBuilder)
    }
}

impl NodeTypes for ArbNode {
    type Primitives = ArbPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = ArbStorage;
    type Payload = ArbEngineTypes;
}

impl<N> Node<N> for ArbNode
where
    N: FullNodeTypes<Types = Self>,
    N::Provider:
        CanonChainTracker<Header = Header> + InMemoryStateAccess<Primitives = ArbPrimitives>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        ArbPoolBuilder,
        ArbPayloadServiceBuilder,
        ArbNetworkBuilder,
        ArbExecutorBuilder,
        ArbConsensusBuilder,
    >;

    type AddOns =
        ArbAddOns<
            NodeAdapter<
                N,
                <Self::ComponentsBuilder as reth_node_builder::components::NodeComponentsBuilder<
                    N,
                >>::Components,
            >,
        >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        RpcAddOns::new(
            ArbEthApiBuilder::default(),
            ArbPayloadValidatorBuilder,
            BasicEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
            Default::default(),
        )
        .extend_rpc_modules(register_arb_rpc)
    }
}

/// EVM config and consensus for reth's offline commands (`re-execute`,
/// `import`, `stage`), so they run the node's ArbOS logic, not stock Ethereum.
pub fn cli_components(chain_spec: Arc<ChainSpec>) -> (ArbEvmConfig, Arc<ArbConsensus<ChainSpec>>) {
    let allow_debug = chainspec::allow_debug_precompiles(&chain_spec);
    (
        ArbEvmConfig::for_offline_execution(chain_spec.clone(), allow_debug),
        Arc::new(ArbConsensus::new_verifying(chain_spec)),
    )
}

/// Builder for the Arbitrum EVM executor component.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArbExecutorBuilder;

impl<N> ExecutorBuilder<N> for ArbExecutorBuilder
where
    N: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = ArbPrimitives>>,
{
    type EVM = ArbEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<N>) -> eyre::Result<Self::EVM> {
        let chain_spec = ctx.chain_spec();
        let allow_debug = chainspec::allow_debug_precompiles(&chain_spec);
        Ok(ArbEvmConfig::with_allow_debug_precompiles(
            chain_spec,
            allow_debug,
        ))
    }
}

/// Registers the `arb_` and `nitroexecution_` RPC namespaces.
fn register_arb_rpc<N, EthApi>(ctx: RpcContext<'_, N, EthApi>) -> eyre::Result<()>
where
    N: FullNodeComponents<
        Types: NodeTypes<ChainSpec = ChainSpec, Primitives = ArbPrimitives>,
        Provider: BlockNumReader
                      + BlockReaderIdExt
                      + HeaderProvider
                      + StateProviderFactory
                      + InMemoryStateAccess<Primitives = ArbPrimitives>
                      + CanonChainTracker<Header = Header>,
    >,
    EthApi: reth_rpc_eth_api::FullEthApiTypes
        + reth_rpc_eth_api::helpers::TraceExt
        + Clone
        + Send
        + Sync
        + 'static,
{
    let arb_api = ArbApiHandler::new(ctx.provider().clone());
    ctx.modules.merge_configured(arb_api.into_rpc())?;

    // Override debug_traceTransaction so the `stylusTracer` named
    // option returns the cached host-I/O records; everything else
    // forwards to the standard handler.
    {
        let debug_api = ctx.registry.debug_api();
        let forwarder: arb_rpc::stylus_debug::DebugForwarder =
            std::sync::Arc::new(move |tx_hash, opts| {
                let api = debug_api.clone();
                Box::pin(async move {
                    api.debug_trace_transaction(tx_hash, opts.unwrap_or_default())
                        .await
                        .map_err(Into::into)
                })
            });
        let stylus_debug = StylusDebugHandler::new(forwarder);
        ctx.modules
            .add_or_replace_configured(stylus_debug.into_rpc())?;
    }

    let chain_spec: Arc<ChainSpec> = ctx.config().chain.clone();
    let allow_debug = chainspec::allow_debug_precompiles(&chain_spec);
    let evm_config = ArbEvmConfig::with_allow_debug_precompiles(chain_spec.clone(), allow_debug);

    let in_memory_state: CanonicalInMemoryState<ArbPrimitives> =
        ctx.provider().canonical_in_memory_state();

    let genesis_block_num = chain_spec.genesis_header().number;

    let flush_interval = std::env::var("ARB_FLUSH_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(producer::DEFAULT_FLUSH_INTERVAL);

    let rollup_args = args::runtime_args();
    validate_live_ipc_mode(&rollup_args)?;
    let verify_every = if rollup_args.state_root_verify_every == 0 {
        std::env::var("ARB_STATE_ROOT_VERIFY_EVERY")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    } else {
        rollup_args.state_root_verify_every
    };
    let state_root_config = StateRootConfig {
        skip_validation: rollup_args.skip_state_root_validation,
        algorithm: rollup_args.state_root_algorithm,
        verify_every,
    };

    let live_ipc = if rollup_args.live_ipc_enabled {
        let live_ipc_uds_path = rollup_args.live_ipc_uds_path.as_ref().ok_or_else(|| {
            eyre::eyre!("--bot-live-exex.uds-path is required when --bot-live-exex.enabled is set")
        })?;
        let publisher = live_ipc::UdsPublisher::bind(
            live_ipc_uds_path.clone(),
            rollup_args.live_ipc_queue_capacity,
            rollup_args.live_ipc_client_queue_capacity,
            rollup_args.live_ipc_replay_capacity,
            rollup_args.live_ipc_replay_byte_capacity,
        )?;
        tracing::info!(
            target: "live_ipc",
            path = %live_ipc_uds_path.display(),
            queue_capacity = rollup_args.live_ipc_queue_capacity,
            client_queue_capacity = rollup_args.live_ipc_client_queue_capacity,
            replay_capacity = rollup_args.live_ipc_replay_capacity,
            replay_byte_capacity = rollup_args.live_ipc_replay_byte_capacity,
            "low-latency canonical state-diff feed enabled"
        );
        Some(Arc::new(publisher))
    } else {
        None
    };

    let block_producer = Arc::new(ArbBlockProducer::new(
        ctx.provider().clone(),
        chain_spec,
        evm_config,
        in_memory_state,
        flush_interval,
        state_root_config,
        live_ipc,
    ));

    let nitro_exec =
        NitroExecutionHandler::new(ctx.provider().clone(), block_producer, genesis_block_num);
    let nitro_rpc = nitro_exec.into_rpc();
    ctx.modules.merge_configured(nitro_rpc.clone())?;
    ctx.auth_module.merge_auth_methods(nitro_rpc)?;

    if state_root_config.skip_validation {
        let mut unavailable = jsonrpsee::RpcModule::new(());
        unavailable.register_method("eth_getProof", |_, _, _| {
            Err::<serde_json::Value, _>(jsonrpsee::types::ErrorObjectOwned::owned(
                -32004,
                "eth_getProof is unavailable while state-root validation is skipped",
                None::<()>,
            ))
        })?;
        unavailable.register_method("eth_getAccount", |_, _, _| {
            Err::<serde_json::Value, _>(jsonrpsee::types::ErrorObjectOwned::owned(
                -32004,
                "eth_getAccount is unavailable while state-root validation is skipped",
                None::<()>,
            ))
        })?;
        ctx.modules.add_or_replace_if_module_configured(
            reth_rpc_server_types::RethRpcModule::Eth,
            unavailable,
        )?;
    }

    Ok(())
}

fn validate_live_ipc_mode(rollup_args: &RollupArgs) -> eyre::Result<()> {
    eyre::ensure!(
        !(rollup_args.live_ipc_enabled && rollup_args.skip_state_root_validation),
        "--bot-live-exex.enabled requires canonical state roots and cannot be combined with \
         --engine.skip-state-root-validation"
    );
    eyre::ensure!(
        !rollup_args.live_ipc_enabled || rollup_args.live_ipc_uds_path.is_some(),
        "--bot-live-exex.uds-path is required when --bot-live-exex.enabled is set"
    );
    Ok(())
}

#[cfg(test)]
mod live_ipc_mode_tests {
    use super::*;

    #[test]
    fn rejects_noncanonical_live_ipc_mode() {
        let args = RollupArgs {
            live_ipc_enabled: true,
            skip_state_root_validation: true,
            live_ipc_uds_path: Some("/private/reth/rarbi-live.sock".into()),
            ..Default::default()
        };
        assert!(validate_live_ipc_mode(&args).is_err());
    }

    #[test]
    fn accepts_each_mode_independently() {
        let canonical_feed = RollupArgs {
            live_ipc_enabled: true,
            live_ipc_uds_path: Some("/private/reth/rarbi-live.sock".into()),
            ..Default::default()
        };
        assert!(validate_live_ipc_mode(&canonical_feed).is_ok());

        let isolated_fast_mode = RollupArgs {
            skip_state_root_validation: true,
            ..Default::default()
        };
        assert!(validate_live_ipc_mode(&isolated_fast_mode).is_ok());
    }

    #[test]
    fn rejects_live_ipc_without_an_explicit_socket_path() {
        let args = RollupArgs {
            live_ipc_enabled: true,
            ..Default::default()
        };
        assert!(validate_live_ipc_mode(&args).is_err());
    }
}

/// Builder for the Arbitrum consensus component.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArbConsensusBuilder;

impl<N> ConsensusBuilder<N> for ArbConsensusBuilder
where
    N: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = ArbPrimitives>>,
{
    type Consensus = Arc<ArbConsensus<ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<N>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(ArbConsensus::new(ctx.chain_spec())))
    }
}

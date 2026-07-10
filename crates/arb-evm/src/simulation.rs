//! ArbOS-correct execution of a speculative user transaction.
//!
//! Unlike a raw `ArbEvm::transact` call, this path runs through
//! `ArbBlockExecutor`, including poster fees, multi-gas accounting, block and
//! transaction limits, fee distribution, retryable hooks, and per-tx
//! finalisation. It deliberately omits block finalisation and persistence.

use std::fmt::Display;

use alloy_consensus::{transaction::Recovered, Header, TxEip1559, TxEip2930, TxLegacy};
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    eth::EthBlockExecutionCtx,
    EvmFactory,
};
use alloy_primitives::{Address, Signature, U256};
use arb_primitives::{ArbTransactionSigned, ArbTypedTransaction};
use reth_chainspec::ChainSpec;
use reth_evm::ConfigureEvm;
use reth_revm::{
    context::result::{ExecutionResult, HaltReason},
    db::{states::bundle_state::BundleRetention, BundleState, State, StateBuilder},
    inspector::{Inspector, NoOpInspector},
    Database, DatabaseRef,
};

use crate::{
    multi_gas::{MultiGasInspector, MultiGasSink},
    sequencer::{apply_account_deletions, augment_bundle_from_cache, filter_unchanged_storage},
    ArbEvm, ArbEvmConfig, ArbSimulationProgress, ArbTransaction,
};

#[derive(Debug, thiserror::Error)]
pub enum ArbSimulationError {
    #[error("unsupported speculative transaction: {0}")]
    UnsupportedTransaction(String),
    #[error("transaction validation failed: {0}")]
    Validation(String),
    #[error("ArbOS simulation execution failed: {0}")]
    Execution(String),
    #[error("ArbOS simulation state extraction failed: {0}")]
    State(String),
}

impl ArbSimulationError {
    pub const fn is_validation(&self) -> bool {
        matches!(self, Self::Validation(_))
    }
}

/// The EVM environment paired with an envelope used by ArbOS for transaction
/// type classification, poster-cost compression, and transaction hashing.
#[derive(Debug, Clone)]
pub struct ArbSimulationTransaction {
    pub environment: ArbTransaction,
    pub envelope: ArbTransactionSigned,
    pub signer: Address,
}

impl ArbSimulationTransaction {
    /// Preserve a real signed envelope for byte-exact poster-cost simulation.
    pub fn from_signed(envelope: ArbTransactionSigned, signer: Address) -> Self {
        use alloy_evm::tx::FromRecoveredTx;
        let environment = ArbTransaction::from_recovered_tx(&envelope, signer);
        Self {
            environment,
            envelope,
            signer,
        }
    }

    /// Build a standard Ethereum envelope for an unsigned speculative TxEnv.
    ///
    /// The fixed dummy signature has the same RLP shape as a production
    /// signature but cannot reproduce its exact Brotli compressibility. Callers
    /// that already have the signed bytes should use `from_signed`.
    pub fn from_environment(
        environment: ArbTransaction,
        default_chain_id: u64,
    ) -> Result<Self, ArbSimulationError> {
        let tx = &environment.0;
        let chain_id = tx.chain_id.unwrap_or(default_chain_id);
        let typed = match tx.tx_type {
            0 => ArbTypedTransaction::Legacy(TxLegacy {
                chain_id: tx.chain_id.or(Some(default_chain_id)),
                nonce: tx.nonce,
                gas_price: tx.gas_price,
                gas_limit: tx.gas_limit,
                to: tx.kind,
                value: tx.value,
                input: tx.data.clone(),
            }),
            1 => ArbTypedTransaction::Eip2930(TxEip2930 {
                chain_id,
                nonce: tx.nonce,
                gas_price: tx.gas_price,
                gas_limit: tx.gas_limit,
                to: tx.kind,
                value: tx.value,
                access_list: tx.access_list.clone(),
                input: tx.data.clone(),
            }),
            2 => ArbTypedTransaction::Eip1559(TxEip1559 {
                chain_id,
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                max_fee_per_gas: tx.gas_price,
                max_priority_fee_per_gas: tx.gas_priority_fee.unwrap_or_default(),
                to: tx.kind,
                value: tx.value,
                access_list: tx.access_list.clone(),
                input: tx.data.clone(),
            }),
            other => {
                return Err(ArbSimulationError::UnsupportedTransaction(format!(
                    "TxEnv type {other}; signed envelope required for EIP-4844, EIP-7702, or ArbOS custom types"
                )))
            }
        };
        let signer = tx.caller;
        // Full-width non-zero scalars model a normal signature's RLP shape and
        // compression cost. Recovery is intentionally bypassed by
        // `Recovered::new_unchecked`.
        let signature = Signature::new(
            U256::from_be_bytes([0x11; 32]),
            U256::from_be_bytes([0x22; 32]),
            false,
        );
        Ok(Self {
            environment,
            envelope: ArbTransactionSigned::new_unhashed(typed, signature),
            signer,
        })
    }
}

#[derive(Debug)]
pub struct ArbSimulationOutput {
    pub result: ExecutionResult<HaltReason>,
    pub bundle: BundleState,
    pub progress: ArbSimulationProgress,
}

pub fn execute_simulated_transaction<DB, E>(
    evm_config: &ArbEvmConfig<ChainSpec>,
    database: DB,
    header: &Header,
    transaction: ArbSimulationTransaction,
    progress: ArbSimulationProgress,
    disable_eip3607: bool,
    disable_nonce_check: bool,
) -> Result<ArbSimulationOutput, ArbSimulationError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
{
    let mut inspector = NoOpInspector;
    execute_simulated_transaction_with_inspector(
        evm_config,
        database,
        header,
        transaction,
        progress,
        disable_eip3607,
        disable_nonce_check,
        &mut inspector,
    )
}

pub fn execute_simulated_transaction_with_inspector<DB, E, I>(
    evm_config: &ArbEvmConfig<ChainSpec>,
    database: DB,
    header: &Header,
    transaction: ArbSimulationTransaction,
    progress: ArbSimulationProgress,
    disable_eip3607: bool,
    disable_nonce_check: bool,
    inspector: &mut I,
) -> Result<ArbSimulationOutput, ArbSimulationError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
    I: for<'a> Inspector<reth_evm::eth::EthEvmContext<&'a mut State<DB>>>,
{
    let mut evm_env = evm_config
        .evm_env(header)
        .map_err(|error| ArbSimulationError::Execution(error.to_string()))?;
    evm_env.cfg_env.disable_eip3607 = disable_eip3607;
    evm_env.cfg_env.disable_nonce_check = disable_nonce_check;
    evm_env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);

    let mut state = StateBuilder::new()
        .with_database(database)
        .with_bundle_update()
        .build();
    let multi_gas_sink = MultiGasSink::default();
    let multi_gas_inspector = MultiGasInspector::with_sink(multi_gas_sink.clone());
    let evm_factory = evm_config.block_executor_factory().evm_factory();

    // A user inspector requires revm's generic dispatch so both it and the
    // consensus multi-gas inspector receive every hook. The sparse path is an
    // experimental node optimization and remains irrelevant to inspected
    // diagnostics.
    let evm = evm_factory.create_evm_with_inspector(
        &mut state,
        evm_env,
        (inspector, multi_gas_inspector),
    );
    let metadata = run_executor(
        evm_config,
        evm,
        header,
        transaction,
        progress,
        multi_gas_sink,
    )?;

    state.merge_transitions(BundleRetention::Reverts);
    let mut bundle = state.take_bundle();
    augment_bundle_from_cache(&mut bundle, &state.cache, &state.database)
        .map_err(|error| ArbSimulationError::State(error.to_string()))?;
    apply_account_deletions(
        &mut bundle,
        &metadata.zombie_accounts,
        &metadata.finalise_deleted,
        &state.database,
    )
    .map_err(|error| ArbSimulationError::State(error.to_string()))?;
    filter_unchanged_storage(&mut bundle);

    Ok(ArbSimulationOutput {
        result: metadata.result,
        bundle,
        progress: metadata.progress,
    })
}

struct ExecutorMetadata {
    result: ExecutionResult<HaltReason>,
    progress: ArbSimulationProgress,
    zombie_accounts: rustc_hash::FxHashSet<Address>,
    finalise_deleted: rustc_hash::FxHashSet<Address>,
}

fn run_executor<'a, DB, E, I>(
    evm_config: &'a ArbEvmConfig<ChainSpec>,
    evm: ArbEvm<&'a mut State<DB>, I>,
    header: &Header,
    transaction: ArbSimulationTransaction,
    progress: ArbSimulationProgress,
    multi_gas_sink: MultiGasSink,
) -> Result<ExecutorMetadata, ArbSimulationError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
    I: Inspector<reth_evm::eth::EthEvmContext<&'a mut State<DB>>> + 'a,
{
    let mut extra = header.extra_data.to_vec();
    extra.resize(32, 0);
    extra.extend_from_slice(&header.nonce.0);
    extra.extend_from_slice(&header.number.to_be_bytes());
    let execution_ctx = EthBlockExecutionCtx {
        tx_count_hint: Some(1),
        parent_hash: header.parent_hash,
        parent_beacon_block_root: header.parent_beacon_block_root,
        ommers: &[],
        withdrawals: None,
        extra_data: extra.into(),
        slot_number: None,
    };
    let chain_id = evm_config.chain_spec().chain().id();
    let mut executor =
        evm_config
            .block_executor_factory()
            .create_arb_executor(evm, execution_ctx, chain_id);
    executor.set_multi_gas_sink(multi_gas_sink);
    executor
        .apply_pre_execution_changes()
        .map_err(|error| ArbSimulationError::Execution(error.to_string()))?;
    executor.set_simulation_progress(progress);

    let recovered = Recovered::new_unchecked(transaction.envelope, transaction.signer);
    let output = executor
        .execute_transaction_without_commit((transaction.environment, recovered))
        .map_err(|error| {
            if error.as_validation().is_some() {
                ArbSimulationError::Validation(error.to_string())
            } else {
                ArbSimulationError::Execution(error.to_string())
            }
        })?;
    let result = output.result.result.clone();
    let _ = executor.commit_transaction(output);
    let progress = executor.simulation_progress();
    let zombie_accounts = executor.zombie_accounts();
    let finalise_deleted = executor.finalise_deleted().clone();
    let (evm, _) = executor
        .finish()
        .map_err(|error| ArbSimulationError::Execution(error.to_string()))?;
    drop(evm);

    Ok(ExecutorMetadata {
        result,
        progress,
        zombie_accounts,
        finalise_deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{EthereumTxEnvelope, SignableTransaction};
    use alloy_primitives::{address, keccak256, Bytes, TxKind, B256};
    use arb_storage::ARBOS_STATE_ADDRESS;
    use arbos::{arbos_state::initialize::bootstrap, burn::SystemBurner};
    use reth_revm::{
        context::result::Output,
        db::{states::bundle_state::BundleRetention, CacheDB, EmptyDB},
        state::AccountInfo,
    };
    use std::sync::Arc;

    const CHAIN_ID: u64 = 1;
    const HEADER_BASE_FEE: u64 = 150_000_000;
    const SENDER: Address = address!("000000000000000000000000000000000000a11c");
    const RECIPIENT: Address = address!("000000000000000000000000000000000000b0b0");

    type TestDb = State<CacheDB<EmptyDB>>;

    fn database() -> TestDb {
        let mut database = StateBuilder::new()
            .with_database(CacheDB::new(EmptyDB::default()))
            .with_bundle_update()
            .build();
        database.insert_account(ARBOS_STATE_ADDRESS, AccountInfo::default());
        bootstrap(
            &mut database,
            CHAIN_ID,
            Address::ZERO,
            Address::ZERO,
            U256::from(100_000_000u64),
            61,
            SystemBurner::new(None, false),
        )
        .unwrap();
        database.insert_account(
            SENDER,
            AccountInfo {
                balance: U256::from(10_000_000_000_000_000_000u128),
                ..Default::default()
            },
        );
        database.merge_transitions(BundleRetention::PlainState);
        database
    }

    fn header() -> Header {
        Header {
            parent_hash: B256::repeat_byte(0x11),
            beneficiary: Address::ZERO,
            number: 42,
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            difficulty: U256::from(1),
            mix_hash: arbos::header::compute_arbos_mixhash(0, 9, 61, false),
            base_fee_per_gas: Some(HEADER_BASE_FEE),
            extra_data: Bytes::from(vec![0; 32]),
            ..Default::default()
        }
    }

    fn signed_1559(to: Address, value: U256, input: Bytes) -> ArbTransactionSigned {
        let transaction = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to),
            value,
            access_list: Default::default(),
            input,
        };
        let signature = Signature::new(U256::from(1), U256::from(2), false);
        ArbTransactionSigned::from_envelope(EthereumTxEnvelope::Eip1559(
            transaction.into_signed(signature),
        ))
    }

    fn config() -> ArbEvmConfig<ChainSpec> {
        ArbEvmConfig::new(Arc::new(ChainSpec::default()))
    }

    #[test]
    fn signed_transfer_runs_full_arbos_hooks_and_returns_exact_bundle() {
        let transaction = ArbSimulationTransaction::from_signed(
            signed_1559(RECIPIENT, U256::from(123_456u64), Bytes::new()),
            SENDER,
        );
        let output = execute_simulated_transaction(
            &config(),
            database(),
            &header(),
            transaction,
            ArbSimulationProgress {
                block_gas_left: Some(1_000_000),
                user_txs_processed: 7,
            },
            false,
            false,
        )
        .unwrap();

        assert!(output.result.is_success(), "{:?}", output.result);
        let sender = output.bundle.state.get(&SENDER).unwrap();
        assert_eq!(sender.info.as_ref().unwrap().nonce, 1);
        let recipient = output.bundle.state.get(&RECIPIENT).unwrap();
        assert_eq!(
            recipient.info.as_ref().unwrap().balance,
            U256::from(123_456u64)
        );
        assert!(
            output
                .bundle
                .state
                .get(&ARBOS_STATE_ADDRESS)
                .is_some_and(|account| !account.storage.is_empty()),
            "ArbOS fee/backlog hooks must contribute state beyond raw EVM execution"
        );
        assert!(output.progress.block_gas_left.unwrap() < 1_000_000);
        assert_eq!(output.progress.user_txs_processed, 8);
    }

    #[test]
    fn arbsys_call_uses_l2_context_and_multigas_executor_path() {
        let selector_hash = keccak256("arbBlockNumber()");
        let selector = &selector_hash.as_slice()[..4];
        let transaction = ArbSimulationTransaction::from_signed(
            signed_1559(
                arb_precompiles::ARBSYS_ADDRESS,
                U256::ZERO,
                Bytes::copy_from_slice(selector),
            ),
            SENDER,
        );
        let output = execute_simulated_transaction(
            &config(),
            database(),
            &header(),
            transaction,
            ArbSimulationProgress {
                block_gas_left: Some(1_000_000),
                user_txs_processed: 2,
            },
            false,
            false,
        )
        .unwrap();

        let ExecutionResult::Success {
            output: Output::Call(bytes),
            ..
        } = output.result
        else {
            panic!("ArbSys simulation did not succeed: {:?}", output.result);
        };
        assert_eq!(U256::from_be_slice(&bytes), U256::from(42u64));
        assert!(output.progress.block_gas_left.unwrap() < 1_000_000);
        assert_eq!(output.progress.user_txs_processed, 3);
    }
}

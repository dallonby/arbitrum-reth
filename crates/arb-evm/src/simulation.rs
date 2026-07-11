//! ArbOS execution of speculative user transactions without persistence.
//!
//! Signed transactions retain their exact poster-cost bytes. Unsigned optimizer
//! probes use a deterministic synthetic envelope and are estimates. Both paths
//! share one `ArbBlockExecutor` per batch, including StartBlock when requested,
//! poster fees, multi-gas accounting, scheduled retryables, fee routing, and
//! per-transaction finalisation.

use std::fmt::Display;

use alloy_consensus::{transaction::Recovered, Header, TxEip1559, TxEip2930, TxLegacy};
use alloy_eips::eip2718::Decodable2718;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    eth::EthBlockExecutionCtx,
    EvmFactory,
};
use alloy_primitives::{keccak256, Address, Bytes, Signature, U256};
use arb_primitives::{tx_types::ArbInternalTx, ArbTransactionSigned, ArbTypedTransaction};
use arbos::internal_tx;
use reth_chainspec::ChainSpec;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::SignedTransaction;
use reth_revm::{
    context::result::{ExecutionResult, HaltReason},
    db::{states::bundle_state::BundleRetention, BundleState, State, StateBuilder},
    inspector::{Inspector, NoOpInspector},
    state::EvmState,
    Database, DatabaseRef,
};

use crate::{
    multi_gas::{MultiGasInspector, MultiGasSink},
    sequencer::{apply_account_deletions, augment_bundle_from_cache, filter_unchanged_storage},
    ArbEvm, ArbEvmConfig, ArbScheduledTxDrain, ArbSimulationProgress, ArbTransaction,
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
    environment: ArbTransaction,
    recovered: Recovered<ArbTransactionSigned>,
}

impl ArbSimulationTransaction {
    /// Preserve a real signed envelope for byte-exact poster-cost simulation.
    pub fn from_signed(recovered: Recovered<ArbTransactionSigned>) -> Self {
        use alloy_evm::tx::FromRecoveredTx;
        let environment = ArbTransaction::from_recovered_tx(recovered.inner(), recovered.signer());
        Self {
            environment,
            recovered,
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
        let mut r = keccak256(b"arb-reth unsigned simulation signature r").0;
        let mut s = keccak256(b"arb-reth unsigned simulation signature s").0;
        // Keeping the top bit clear produces non-zero scalars below the secp256k1
        // order while retaining high entropy for a realistic Brotli estimate.
        r[0] &= 0x7f;
        s[0] &= 0x7f;
        let signature = Signature::new(U256::from_be_bytes(r), U256::from_be_bytes(s), false);
        let envelope = ArbTransactionSigned::new_unhashed(typed, signature);
        Ok(Self {
            environment,
            recovered: Recovered::new_unchecked(envelope, signer),
        })
    }

    fn into_parts(self) -> (ArbTransaction, Recovered<ArbTransactionSigned>) {
        (self.environment, self.recovered)
    }
}

/// Best-known inputs for the target block's StartBlock internal transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArbSimulationBlockStart {
    pub l1_base_fee: U256,
    pub l1_block_number: u64,
    pub time_passed: u64,
}

#[derive(Debug)]
pub struct ArbSimulationOutput {
    pub result: ExecutionResult<HaltReason>,
    pub bundle: BundleState,
    pub progress: ArbSimulationProgress,
}

#[derive(Debug)]
pub struct ArbSimulationTransactionOutput {
    pub result: ExecutionResult<HaltReason>,
    /// The core EVM writes for this transaction. `ArbSimulationBatchOutput::bundle`
    /// is authoritative for the cumulative EVM and ArbOS state transition.
    pub state: EvmState,
}

#[derive(Debug)]
pub struct ArbSimulationBatchOutput {
    pub transactions: Vec<Result<ArbSimulationTransactionOutput, ArbSimulationError>>,
    pub bundle: BundleState,
    pub progress: ArbSimulationProgress,
}

pub fn execute_simulated_transaction<DB, E>(
    evm_config: &ArbEvmConfig<ChainSpec>,
    database: DB,
    header: &Header,
    transaction: ArbSimulationTransaction,
    progress: ArbSimulationProgress,
    block_start: Option<ArbSimulationBlockStart>,
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
        block_start,
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
    block_start: Option<ArbSimulationBlockStart>,
    disable_eip3607: bool,
    disable_nonce_check: bool,
    inspector: &mut I,
) -> Result<ArbSimulationOutput, ArbSimulationError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
    I: for<'a> Inspector<reth_evm::eth::EthEvmContext<&'a mut State<DB>>>,
{
    let mut output = execute_simulated_batch_with_inspector(
        evm_config,
        database,
        header,
        vec![transaction],
        progress,
        block_start,
        disable_eip3607,
        disable_nonce_check,
        inspector,
    )?;
    let transaction = output.transactions.pop().ok_or_else(|| {
        ArbSimulationError::Execution(
            "single-transaction simulation returned no transaction result".into(),
        )
    })??;
    Ok(ArbSimulationOutput {
        result: transaction.result,
        bundle: output.bundle,
        progress: output.progress,
    })
}

pub fn execute_simulated_batch<DB, E>(
    evm_config: &ArbEvmConfig<ChainSpec>,
    database: DB,
    header: &Header,
    transactions: Vec<ArbSimulationTransaction>,
    progress: ArbSimulationProgress,
    block_start: Option<ArbSimulationBlockStart>,
    disable_eip3607: bool,
    disable_nonce_check: bool,
) -> Result<ArbSimulationBatchOutput, ArbSimulationError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
{
    let mut inspector = NoOpInspector;
    execute_simulated_batch_with_inspector(
        evm_config,
        database,
        header,
        transactions,
        progress,
        block_start,
        disable_eip3607,
        disable_nonce_check,
        &mut inspector,
    )
}

pub fn execute_simulated_batch_with_inspector<DB, E, I>(
    evm_config: &ArbEvmConfig<ChainSpec>,
    database: DB,
    header: &Header,
    transactions: Vec<ArbSimulationTransaction>,
    progress: ArbSimulationProgress,
    block_start: Option<ArbSimulationBlockStart>,
    disable_eip3607: bool,
    disable_nonce_check: bool,
    inspector: &mut I,
) -> Result<ArbSimulationBatchOutput, ArbSimulationError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
    I: for<'a> Inspector<reth_evm::eth::EthEvmContext<&'a mut State<DB>>>,
{
    if !progress.block_initialized() {
        let start = block_start.ok_or_else(|| {
            ArbSimulationError::Execution(
                "uninitialized simulation target requires StartBlock inputs".into(),
            )
        })?;
        let header_l1_block = crate::config::l1_block_number_from_mix_hash(&header.mix_hash);
        if start.l1_block_number != header_l1_block {
            return Err(ArbSimulationError::Execution(format!(
                "StartBlock L1 number {} does not match header mix-hash L1 number {header_l1_block}",
                start.l1_block_number
            )));
        }
    }

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
    let metadata = run_batch_executor(
        evm_config,
        evm,
        header,
        transactions,
        progress,
        block_start,
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

    Ok(ArbSimulationBatchOutput {
        transactions: metadata.transactions,
        bundle,
        progress: metadata.progress,
    })
}

struct ExecutorMetadata {
    transactions: Vec<Result<ArbSimulationTransactionOutput, ArbSimulationError>>,
    progress: ArbSimulationProgress,
    zombie_accounts: rustc_hash::FxHashSet<Address>,
    finalise_deleted: rustc_hash::FxHashSet<Address>,
}

fn run_batch_executor<'a, DB, E, I>(
    evm_config: &'a ArbEvmConfig<ChainSpec>,
    evm: ArbEvm<&'a mut State<DB>, I>,
    header: &Header,
    transactions: Vec<ArbSimulationTransaction>,
    progress: ArbSimulationProgress,
    block_start: Option<ArbSimulationBlockStart>,
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
        tx_count_hint: Some(transactions.len().saturating_add(1)),
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
    if progress.block_initialized() {
        executor
            .prepare_simulation_continuation()
            .map_err(|error| ArbSimulationError::Execution(error.to_string()))?;
    } else {
        executor
            .apply_pre_execution_changes()
            .map_err(|error| ArbSimulationError::Execution(error.to_string()))?;
        if let Some(block_start) = block_start {
            execute_start_block(&mut executor, chain_id, header.number, block_start)?;
        }
    }
    executor.set_simulation_progress(progress);

    let mut transaction_outputs = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        let (environment, recovered) = transaction.into_parts();
        match executor.execute_transaction_without_commit((environment, recovered)) {
            Ok(output) => {
                let result = output.result.result.clone();
                let state = output.result.state.clone();
                let _ = executor.commit_transaction(output);
                drain_scheduled_transactions(&mut executor)?;
                transaction_outputs.push(Ok(ArbSimulationTransactionOutput { result, state }));
            }
            Err(error) if error.as_validation().is_some() => {
                transaction_outputs.push(Err(ArbSimulationError::Validation(error.to_string())))
            }
            Err(error) => {
                transaction_outputs.push(Err(ArbSimulationError::Execution(error.to_string())))
            }
        }
    }
    let progress = executor.simulation_progress();
    let zombie_accounts = executor.zombie_accounts();
    let finalise_deleted = executor.finalise_deleted().clone();
    let (evm, _) = executor
        .finish()
        .map_err(|error| ArbSimulationError::Execution(error.to_string()))?;
    drop(evm);

    Ok(ExecutorMetadata {
        transactions: transaction_outputs,
        progress,
        zombie_accounts,
        finalise_deleted,
    })
}

fn create_internal_transaction(chain_id: u64, data: &[u8]) -> ArbTransactionSigned {
    let transaction = ArbTypedTransaction::Internal(ArbInternalTx {
        chain_id: U256::from(chain_id),
        data: Bytes::copy_from_slice(data),
    });
    let signature = Signature::new(U256::ZERO, U256::ZERO, false);
    ArbTransactionSigned::new_unhashed(transaction, signature)
}

fn execute_start_block<E>(
    executor: &mut E,
    chain_id: u64,
    l2_block_number: u64,
    block_start: ArbSimulationBlockStart,
) -> Result<(), ArbSimulationError>
where
    E: BlockExecutor<Transaction = ArbTransactionSigned>,
{
    let data = internal_tx::encode_start_block(
        block_start.l1_base_fee,
        block_start.l1_block_number,
        l2_block_number,
        block_start.time_passed,
    );
    let transaction = create_internal_transaction(chain_id, &data);
    let recovered = transaction.try_into_recovered().map_err(|error| {
        ArbSimulationError::Execution(format!("StartBlock recovery failed: {error:?}"))
    })?;
    let output = executor
        .execute_transaction_without_commit(recovered)
        .map_err(|error| ArbSimulationError::Execution(format!("StartBlock failed: {error}")))?;
    let _ = executor.commit_transaction(output);
    Ok(())
}

fn drain_scheduled_transactions<E>(executor: &mut E) -> Result<(), ArbSimulationError>
where
    E: BlockExecutor<Transaction = ArbTransactionSigned> + ArbScheduledTxDrain,
{
    loop {
        let scheduled = executor.drain_scheduled_txs();
        if scheduled.is_empty() {
            return Ok(());
        }
        for encoded in scheduled {
            let transaction =
                ArbTransactionSigned::decode_2718(&mut &encoded[..]).map_err(|error| {
                    ArbSimulationError::Execution(format!(
                        "scheduled retryable decode failed: {error}"
                    ))
                })?;
            let recovered = transaction.try_into_recovered().map_err(|error| {
                ArbSimulationError::Execution(format!(
                    "scheduled retryable recovery failed: {error:?}"
                ))
            })?;
            let output = executor
                .execute_transaction_without_commit(recovered)
                .map_err(|error| {
                    ArbSimulationError::Execution(format!(
                        "scheduled retryable execution failed: {error}"
                    ))
                })?;
            let _ = executor.commit_transaction(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{
        crypto::secp256k1::sign_message, EthereumTxEnvelope, SignableTransaction,
    };
    use alloy_primitives::{address, b256, hex, keccak256, Bytes, TxKind, B256};
    use arb_storage::ARBOS_STATE_ADDRESS;
    use arbos::{arbos_state::initialize::bootstrap, burn::SystemBurner};
    use reth_revm::{
        context::result::Output,
        db::{states::bundle_state::BundleRetention, CacheDB, EmptyDB},
        state::{AccountInfo, Bytecode},
    };
    use std::sync::Arc;

    const CHAIN_ID: u64 = 4663;
    const HEADER_BASE_FEE: u64 = 150_000_000;
    const SENDER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const SIGNING_KEY: B256 =
        b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const RECIPIENT: Address = address!("000000000000000000000000000000000000b0b0");
    const L1_NUMBER_CONTRACT: Address = address!("0000000000000000000000000000000000000043");
    const STYLUS_PROGRAM: Address = address!("2dc1bad4e0a3af9acf003d65dea54dc568e787d2");
    const STYLUS_PROGRAM_HEX: &str = include_str!(concat!(
        "../../arb-spec-tests/fixtures/regression/stylus_nested_oog/program.hex"
    ));

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
        let code = Bytecode::new_raw(Bytes::from_static(&[
            0x43, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ]));
        database.insert_account(
            L1_NUMBER_CONTRACT,
            AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
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

    fn signed_1559(nonce: u64, to: Address, value: U256, input: Bytes) -> ArbTransactionSigned {
        let transaction = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to),
            value,
            access_list: Default::default(),
            input,
        };
        let signature = sign_message(SIGNING_KEY, transaction.signature_hash()).unwrap();
        ArbTransactionSigned::from_envelope(EthereumTxEnvelope::Eip1559(
            transaction.into_signed(signature),
        ))
    }

    fn config() -> ArbEvmConfig<ChainSpec> {
        let mut chain_spec = ChainSpec::default();
        chain_spec.chain = reth_chainspec::Chain::from(CHAIN_ID);
        ArbEvmConfig::new(Arc::new(chain_spec))
    }

    fn stylus_database() -> TestDb {
        let mut database = database();
        let code = hex::decode(STYLUS_PROGRAM_HEX.trim().trim_start_matches("0x")).unwrap();
        arb_storage::set_account_code(&mut database, STYLUS_PROGRAM, Bytes::from(code.clone()));
        let code_hash = keccak256(&code);
        let wasm = arb_stylus::decompress_wasm(&code).unwrap();
        let mut gas = u64::MAX;
        let activation = arb_stylus::activate_program(
            &wasm,
            code_hash.as_ref(),
            3,
            61,
            u16::MAX,
            false,
            &mut gas,
        )
        .unwrap();
        {
            let arb_state =
                arbos::arbos_state::ArbosState::open(&mut database, SystemBurner::new(None, false))
                    .unwrap();
            // SAFETY: the detached test state has no concurrent borrower.
            let backend = unsafe { arb_state.backing_storage.state_mut() };
            let mut params = arb_state.programs.params(backend).unwrap();
            while params.version < 3 {
                params.upgrade_to_version(params.version + 1).unwrap();
            }
            arb_state.programs.save_params(backend, &params).unwrap();
            arb_state
                .programs
                .set_module_hash(backend, code_hash, activation.module_hash)
                .unwrap();
            arb_state
                .programs
                .set_program(
                    backend,
                    code_hash,
                    arbos::programs::Program {
                        version: 3,
                        init_cost: activation.init_gas,
                        cached_cost: activation.cached_init_gas,
                        footprint: activation.footprint,
                        asm_estimate_kb: activation.asm_estimate.div_ceil(1024),
                        activated_at: arbos::programs::hours_since_arbitrum(header().timestamp),
                        age_seconds: 0,
                        cached: false,
                    },
                )
                .unwrap();
        }
        database.merge_transitions(BundleRetention::PlainState);
        database
    }

    fn apply_bundle(database: &mut TestDb, bundle: &BundleState) {
        for (address, bundled) in &bundle.state {
            let Some(info) = bundled.info.clone() else {
                database.insert_not_existing(*address);
                continue;
            };
            let mut storage = database
                .cache
                .accounts
                .get(address)
                .and_then(|cached| cached.account.as_ref())
                .map(|account| account.storage.clone())
                .unwrap_or_default();
            if bundled.status.is_storage_known() {
                storage.clear();
            }
            for (slot, value) in &bundled.storage {
                storage.insert(*slot, value.present_value);
            }
            database.insert_account_with_storage(*address, info, storage);
        }
    }

    fn assert_same_cached_state(left: &TestDb, right: &TestDb) {
        let addresses = left
            .cache
            .accounts
            .keys()
            .chain(right.cache.accounts.keys())
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        for address in addresses {
            let left_account = left
                .cache
                .accounts
                .get(&address)
                .and_then(|cached| cached.account.as_ref());
            let right_account = right
                .cache
                .accounts
                .get(&address)
                .and_then(|cached| cached.account.as_ref());
            assert_eq!(left_account, right_account, "state differs at {address}");
        }
    }

    fn execute_canonical_batch(
        transactions: Vec<ArbSimulationTransaction>,
        block_start: ArbSimulationBlockStart,
    ) -> (BundleState, ArbSimulationProgress) {
        let config = config();
        let header = header();
        let mut evm_env = config.evm_env(&header).unwrap();
        evm_env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);
        let mut state = StateBuilder::new()
            .with_database(database())
            .with_bundle_update()
            .build();
        let multi_gas_sink = MultiGasSink::default();
        let evm = config
            .block_executor_factory()
            .evm_factory()
            .create_evm_with_inspector(
                &mut state,
                evm_env,
                (
                    NoOpInspector,
                    MultiGasInspector::with_sink(multi_gas_sink.clone()),
                ),
            );
        let mut extra = header.extra_data.to_vec();
        extra.resize(32, 0);
        extra.extend_from_slice(&header.nonce.0);
        extra.extend_from_slice(&header.number.to_be_bytes());
        let execution_ctx = EthBlockExecutionCtx {
            tx_count_hint: Some(transactions.len().saturating_add(1)),
            parent_hash: header.parent_hash,
            parent_beacon_block_root: header.parent_beacon_block_root,
            ommers: &[],
            withdrawals: None,
            extra_data: extra.into(),
            slot_number: None,
        };
        let mut executor =
            config
                .block_executor_factory()
                .create_arb_executor(evm, execution_ctx, CHAIN_ID);
        executor.set_multi_gas_sink(multi_gas_sink);
        executor.apply_pre_execution_changes().unwrap();
        execute_start_block(&mut executor, CHAIN_ID, header.number, block_start).unwrap();
        for transaction in transactions {
            let (environment, recovered) = transaction.into_parts();
            let output = executor
                .execute_transaction_without_commit((environment, recovered))
                .unwrap();
            let _ = executor.commit_transaction(output);
            drain_scheduled_transactions(&mut executor).unwrap();
        }
        let progress = executor.simulation_progress();
        let zombie_accounts = executor.zombie_accounts();
        let finalise_deleted = executor.finalise_deleted().clone();
        let (evm, _) = executor.finish().unwrap();
        drop(evm);

        state.merge_transitions(BundleRetention::Reverts);
        let mut bundle = state.take_bundle();
        augment_bundle_from_cache(&mut bundle, &state.cache, &state.database).unwrap();
        apply_account_deletions(
            &mut bundle,
            &zombie_accounts,
            &finalise_deleted,
            &state.database,
        )
        .unwrap();
        filter_unchanged_storage(&mut bundle);
        (bundle, progress)
    }

    #[test]
    fn signed_transfer_runs_full_arbos_hooks_and_returns_exact_bundle() {
        let transaction = ArbSimulationTransaction::from_signed(
            signed_1559(0, RECIPIENT, U256::from(123_456u64), Bytes::new())
                .try_into_recovered()
                .unwrap(),
        );
        let output = execute_simulated_transaction(
            &config(),
            database(),
            &header(),
            transaction,
            ArbSimulationProgress::initialized(Some(1_000_000), 7),
            None,
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
        assert!(output.progress.block_gas_left().unwrap() < 1_000_000);
        assert_eq!(output.progress.user_txs_processed(), 8);
    }

    #[test]
    fn arbsys_call_uses_l2_context_and_multigas_executor_path() {
        let selector_hash = keccak256("arbBlockNumber()");
        let selector = &selector_hash.as_slice()[..4];
        let transaction = ArbSimulationTransaction::from_signed(
            signed_1559(
                0,
                arb_precompiles::ARBSYS_ADDRESS,
                U256::ZERO,
                Bytes::copy_from_slice(selector),
            )
            .try_into_recovered()
            .unwrap(),
        );
        let output = execute_simulated_transaction(
            &config(),
            database(),
            &header(),
            transaction,
            ArbSimulationProgress::initialized(Some(1_000_000), 2),
            None,
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
        assert!(output.progress.block_gas_left().unwrap() < 1_000_000);
        assert_eq!(output.progress.user_txs_processed(), 3);
    }

    #[test]
    fn committed_two_transaction_continuation_matches_one_canonical_executor() {
        let transaction = |nonce, value| {
            ArbSimulationTransaction::from_signed(
                signed_1559(nonce, RECIPIENT, U256::from(value), Bytes::new())
                    .try_into_recovered()
                    .unwrap(),
            )
        };
        let block_start = ArbSimulationBlockStart {
            l1_base_fee: U256::from(1_000_000_000u64),
            l1_block_number: 9,
            time_passed: 0,
        };

        let batch = execute_simulated_batch(
            &config(),
            database(),
            &header(),
            vec![transaction(0, 123u64), transaction(1, 456u64)],
            ArbSimulationProgress::default(),
            Some(block_start),
            false,
            false,
        )
        .unwrap();
        assert!(batch.transactions.iter().all(|result| result
            .as_ref()
            .is_ok_and(|output| output.result.is_success())));
        let (canonical_bundle, canonical_progress) = execute_canonical_batch(
            vec![transaction(0, 123u64), transaction(1, 456u64)],
            block_start,
        );

        let first = execute_simulated_transaction(
            &config(),
            database(),
            &header(),
            transaction(0, 123u64),
            ArbSimulationProgress::default(),
            Some(block_start),
            false,
            false,
        )
        .unwrap();
        let mut second_database = database();
        apply_bundle(&mut second_database, &first.bundle);
        let second = execute_simulated_transaction(
            &config(),
            second_database,
            &header(),
            transaction(1, 456u64),
            first.progress,
            Some(block_start),
            false,
            false,
        )
        .unwrap();

        let mut batch_state = database();
        apply_bundle(&mut batch_state, &batch.bundle);
        let mut canonical_state = database();
        apply_bundle(&mut canonical_state, &canonical_bundle);
        assert_same_cached_state(&batch_state, &canonical_state);
        assert_eq!(batch.progress, canonical_progress);
        let mut continued_state = database();
        apply_bundle(&mut continued_state, &first.bundle);
        apply_bundle(&mut continued_state, &second.bundle);
        assert_same_cached_state(&batch_state, &continued_state);
        assert_eq!(batch.progress, second.progress);
        assert!(batch.progress.block_initialized());
        assert_eq!(batch.progress.user_txs_processed(), 2);
    }

    #[test]
    fn predicted_startblock_l1_number_matches_evm_number_context() {
        let mut target_header = header();
        target_header.mix_hash = arbos::header::compute_arbos_mixhash(0, 10, 61, false);
        let transaction = ArbSimulationTransaction::from_signed(
            signed_1559(0, L1_NUMBER_CONTRACT, U256::ZERO, Bytes::new())
                .try_into_recovered()
                .unwrap(),
        );
        let output = execute_simulated_transaction(
            &config(),
            database(),
            &target_header,
            transaction,
            ArbSimulationProgress::default(),
            Some(ArbSimulationBlockStart {
                l1_base_fee: U256::from(1_000_000_000u64),
                l1_block_number: 10,
                time_passed: 0,
            }),
            false,
            false,
        )
        .unwrap();

        let ExecutionResult::Success {
            output: Output::Call(bytes),
            ..
        } = output.result
        else {
            panic!("L1 NUMBER probe did not succeed: {:?}", output.result);
        };
        assert_eq!(U256::from_be_slice(&bytes), U256::from(10u64));

        let mismatch = execute_simulated_batch(
            &config(),
            database(),
            &target_header,
            Vec::new(),
            ArbSimulationProgress::default(),
            Some(ArbSimulationBlockStart {
                l1_base_fee: U256::ZERO,
                l1_block_number: 11,
                time_passed: 0,
            }),
            false,
            false,
        )
        .unwrap_err();
        assert!(mismatch
            .to_string()
            .contains("does not match header mix-hash"));
    }

    #[test]
    fn continuation_preserves_arbos61_recent_wasm_lru() {
        let wasm_hash = B256::repeat_byte(0xa5);
        let mut progress = ArbSimulationProgress::initialized(Some(1_000_000), 0);
        progress.seed_recent_wasm(wasm_hash, 32);
        let transaction = ArbSimulationTransaction::from_signed(
            signed_1559(0, RECIPIENT, U256::from(1u64), Bytes::new())
                .try_into_recovered()
                .unwrap(),
        );
        let output = execute_simulated_transaction(
            &config(),
            database(),
            &header(),
            transaction,
            progress,
            None,
            false,
            false,
        )
        .unwrap();

        assert!(output.progress.contains_recent_wasm(&wasm_hash));
    }

    #[test]
    fn repeated_stylus_call_split_continuation_matches_single_executor_gas() {
        let transaction = |nonce| {
            ArbSimulationTransaction::from_signed(
                signed_1559(nonce, STYLUS_PROGRAM, U256::ZERO, Bytes::new())
                    .try_into_recovered()
                    .unwrap(),
            )
        };
        let block_start = ArbSimulationBlockStart {
            l1_base_fee: U256::from(1_000_000_000u64),
            l1_block_number: 9,
            time_passed: 0,
        };
        let initialized = execute_simulated_batch(
            &config(),
            stylus_database(),
            &header(),
            Vec::new(),
            ArbSimulationProgress::default(),
            Some(block_start),
            false,
            false,
        )
        .unwrap();

        let mut batch_database = stylus_database();
        apply_bundle(&mut batch_database, &initialized.bundle);
        let batch = execute_simulated_batch(
            &config(),
            batch_database,
            &header(),
            vec![transaction(0), transaction(1)],
            initialized.progress.clone(),
            None,
            false,
            false,
        )
        .unwrap();
        let batch_second_gas = batch.transactions[1].as_ref().unwrap().result.tx_gas_used();

        let mut first_database = stylus_database();
        apply_bundle(&mut first_database, &initialized.bundle);
        let first = execute_simulated_transaction(
            &config(),
            first_database,
            &header(),
            transaction(0),
            initialized.progress,
            None,
            false,
            false,
        )
        .unwrap();
        let mut second_database = stylus_database();
        apply_bundle(&mut second_database, &initialized.bundle);
        apply_bundle(&mut second_database, &first.bundle);
        let second = execute_simulated_transaction(
            &config(),
            second_database,
            &header(),
            transaction(1),
            first.progress,
            None,
            false,
            false,
        )
        .unwrap();

        assert_eq!(second.result.tx_gas_used(), batch_second_gas);
        assert_eq!(second.progress, batch.progress);
    }
}

//! Persistence-free execution of one Nitro sequencer message.
//!
//! The node producer and latency-sensitive consumers need the same ArbOS
//! transaction pipeline, but only the node should calculate a trie root or
//! write MDBX.  This module executes against an arbitrary revm database and
//! returns an atomic [`BundleState`].  A caller can discard the bundle on any
//! error or publish it to an in-memory overlay after the complete message has
//! succeeded.

use std::fmt::Display;

use alloy_consensus::Header;
use alloy_eips::eip2718::Decodable2718;
use alloy_evm::{
    block::{BlockExecutor, BlockExecutorFactory},
    EvmFactory,
};
use alloy_primitives::{Address, Bytes, B256, B64, U256};
use arb_primitives::{
    tx_types::ArbInternalTx, ArbReceipt, ArbTransactionSigned, ArbTypedTransaction,
};
use arbos::{
    header::{
        derive_arb_header_info, extract_arbos_version_from_mix_hash,
        extract_l1_block_number_from_mix_hash, extract_send_count_from_mix_hash, read_l2_base_fee,
    },
    internal_tx,
    parse_l2::{parse_l2_transactions, parsed_tx_to_signed, ParsedTransaction},
};
use reth_chainspec::ChainSpec;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::SignedTransaction;
use reth_revm::{
    db::{
        states::bundle_state::BundleRetention, AccountStatus as BundleAccountStatus, BundleState,
        StateBuilder,
    },
    Database, DatabaseRef,
};

use crate::{config::ArbEvmConfig, multi_gas, ArbSimulationProgress};

/// Parent/result metadata needed to execute the next sequencer message.
///
/// `hash` is kept separately because low-latency consumers receive the
/// sequencer's block hash before calculating a state root locally.  The other
/// fields are exactly those consumed by the ArbOS environment and StartBlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerBlockState {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
    pub mix_hash: B256,
    pub beneficiary: Address,
    pub delayed_messages_read: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas: Option<u64>,
    pub extra_data: Bytes,
}

impl SequencerBlockState {
    pub fn from_header(header: &Header, hash: B256) -> Self {
        Self {
            number: header.number,
            hash,
            timestamp: header.timestamp,
            mix_hash: header.mix_hash,
            beneficiary: header.beneficiary,
            delayed_messages_read: u64::from_be_bytes(header.nonce.0),
            gas_limit: header.gas_limit,
            base_fee_per_gas: header.base_fee_per_gas,
            extra_data: header.extra_data.clone(),
        }
    }
}

/// Execution-relevant fields from one ordered Nitro broadcast message.
#[derive(Debug, Clone)]
pub struct SequencerBlockInput {
    pub sequence_number: u64,
    pub block_hash: B256,
    pub kind: u8,
    pub sender: Address,
    pub l1_block_number: u64,
    pub l1_timestamp: u64,
    pub request_id: Option<B256>,
    pub l1_base_fee: Option<U256>,
    pub l2_msg: Vec<u8>,
    pub delayed_messages_read: u64,
    pub batch_gas_cost: Option<u64>,
    pub batch_data_stats: Option<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedSequencerTransaction {
    pub parsed_index: usize,
    pub reason: String,
}

/// Atomic output of one complete sequencer-message execution.
#[derive(Debug)]
pub struct ExecutedSequencerBlock {
    pub state: SequencerBlockState,
    pub bundle: BundleState,
    pub transactions: Vec<ArbTransactionSigned>,
    /// User-visible transaction executions, excluding StartBlock and batch
    /// posting reports. Scheduled retryables are included because their state
    /// and logs are externally observable and relevant to MEV consumers.
    pub user_executions: Vec<SequencerTransactionExecution>,
    pub receipts: Vec<ArbReceipt>,
    pub gas_used: u64,
    /// Remaining per-block gas and user-transaction count after the complete
    /// sequencer message. Speculative transactions appended by a low-latency
    /// consumer must resume these counters rather than starting a fresh block.
    pub simulation_progress: ArbSimulationProgress,
    pub skipped: Vec<SkippedSequencerTransaction>,
}

#[derive(Debug)]
pub struct SequencerTransactionExecution {
    pub transaction: ArbTransactionSigned,
    pub result: reth_revm::context::result::ExecutionResult<reth_revm::context::result::HaltReason>,
    pub state: reth_revm::state::EvmState,
}

#[derive(Debug, thiserror::Error)]
pub enum SequencerExecutionError {
    #[error("sequencer continuity: expected block {expected}, received sequence {actual}")]
    Continuity { expected: u64, actual: u64 },
    #[error("sequencer message parse: {0}")]
    Parse(String),
    #[error("sequencer state access: {0}")]
    State(String),
    #[error("sequencer execution: {0}")]
    Execution(String),
}

/// Execute a complete ordered sequencer message without persistence or trie
/// work.
///
/// The supplied database is treated as the immutable parent state.  All
/// changes are accumulated in a revm `State`, including direct ArbOS storage
/// mutations which do not originate in an EVM result.  Nothing is written to
/// `database`; the caller receives one bundle only after StartBlock, user
/// transactions, scheduled retryables and block finalisation all succeed.
pub fn execute_sequencer_block<DB, E>(
    evm_config: &ArbEvmConfig<ChainSpec>,
    database: DB,
    parent: &SequencerBlockState,
    input: &SequencerBlockInput,
) -> Result<ExecutedSequencerBlock, SequencerExecutionError>
where
    DB: Database<Error = E> + DatabaseRef<Error = E> + std::fmt::Debug,
    E: std::error::Error + Display + Send + Sync + 'static,
{
    let l2_block_number = parent.number.saturating_add(1);
    if input.sequence_number != l2_block_number {
        return Err(SequencerExecutionError::Continuity {
            expected: l2_block_number,
            actual: input.sequence_number,
        });
    }

    let chain_id = evm_config.chain_spec().chain().id();
    let parsed_txs = parse_l2_transactions(
        input.kind,
        input.sender,
        &input.l2_msg,
        input.request_id,
        input.l1_base_fee,
        chain_id,
    )
    .map_err(|error| SequencerExecutionError::Parse(error.to_string()))?;

    let timestamp = input.l1_timestamp.max(parent.timestamp);
    let time_passed = timestamp.saturating_sub(parent.timestamp);
    let parent_arbos_version = extract_arbos_version_from_mix_hash(parent.mix_hash);
    let parent_l1_block = extract_l1_block_number_from_mix_hash(parent.mix_hash);
    let parent_send_count = extract_send_count_from_mix_hash(parent.mix_hash);
    let block_l1_block_number = input.l1_block_number.max(parent_l1_block);
    let provisional_mix_hash = arbos::header::compute_arbos_mixhash(
        parent_send_count,
        block_l1_block_number,
        parent_arbos_version,
        false,
    );

    let read_parent_slot = |address: Address, slot: B256| {
        database
            .storage_ref(address, U256::from_be_bytes(slot.0))
            .map(Some)
    };
    let l2_base_fee = read_l2_base_fee(&read_parent_slot)
        .map_err(|error| SequencerExecutionError::State(error.to_string()))?
        .or(parent.base_fee_per_gas);

    let provisional_header = Header {
        parent_hash: parent.hash,
        beneficiary: input.sender,
        timestamp,
        mix_hash: provisional_mix_hash,
        nonce: B64::from(input.delayed_messages_read.to_be_bytes()),
        base_fee_per_gas: l2_base_fee,
        number: l2_block_number,
        gas_limit: parent.gas_limit,
        difficulty: U256::from(1),
        ..Default::default()
    };
    let evm_env = evm_config
        .evm_env(&provisional_header)
        .map_err(|error| SequencerExecutionError::Execution(error.to_string()))?;

    let mut state = StateBuilder::new()
        .with_database(database)
        .with_bundle_update()
        .build();

    let mut exec_extra = parent.extra_data.to_vec();
    exec_extra.resize(32, 0);
    exec_extra.extend_from_slice(&input.delayed_messages_read.to_be_bytes());
    let exec_ctx = alloy_evm::eth::EthBlockExecutionCtx {
        tx_count_hint: Some(parsed_txs.len().saturating_add(2)),
        parent_hash: parent.hash,
        parent_beacon_block_root: None,
        ommers: &[],
        withdrawals: None,
        extra_data: exec_extra.into(),
        slot_number: None,
    };

    let multi_gas_sink = multi_gas::MultiGasSink::default();
    let evm_factory = evm_config.block_executor_factory().evm_factory();
    let inspector = multi_gas::MultiGasInspector::with_sink(multi_gas_sink.clone());
    let evm = if multi_gas::sparse_inspector_enabled() {
        evm_factory.create_evm_with_sparse_multigas_inspector(
            &mut state,
            evm_env.clone(),
            inspector,
        )
    } else {
        evm_factory.create_evm_with_inspector(&mut state, evm_env.clone(), inspector)
    };
    let mut executor = evm_config
        .block_executor_factory()
        .create_arb_executor(evm, exec_ctx, chain_id);
    executor.set_multi_gas_sink(multi_gas_sink);
    executor.arb_ctx.l2_block_number = l2_block_number;
    executor.arb_ctx.l1_block_number = block_l1_block_number;
    executor
        .apply_pre_execution_changes()
        .map_err(|error| SequencerExecutionError::Execution(format!("pre-exec: {error}")))?;
    // `apply_pre_execution_changes` fills ArbSys's complete 256-block hash
    // window through `Database::block_hash`. Rarbi's CacheDb delegates older
    // committed hashes to its exact MDBX anchor and retains every UDS/direct
    // suffix hash in its snapshot, so unlike the node producer it has no
    // invisible unflushed-header gap here. Re-seeding the immediate parent is
    // idempotent and protects generic databases that omit their current hash.
    executor
        .precompile_ctx
        .block
        .cache_l2_block_hash(parent.number, parent.hash);

    let mut transactions = Vec::with_capacity(parsed_txs.len().saturating_add(1));
    let mut user_executions = Vec::with_capacity(parsed_txs.len());
    let mut skipped = Vec::new();

    let start_block_data = internal_tx::encode_start_block(
        input.l1_base_fee.unwrap_or(U256::ZERO),
        input.l1_block_number,
        l2_block_number,
        time_passed,
    );
    let start_block = create_internal_tx(chain_id, &start_block_data);
    execute_and_commit(&mut executor, &start_block, "StartBlock")?;
    transactions.push(start_block);

    for (parsed_index, parsed) in parsed_txs.iter().enumerate() {
        match parsed {
            ParsedTransaction::InternalStartBlock { .. } => continue,
            ParsedTransaction::BatchPostingReport {
                batch_timestamp,
                batch_poster,
                batch_number,
                l1_base_fee_estimate,
                extra_gas,
                ..
            } => {
                let report_data =
                    if parent_arbos_version >= arb_chainspec::arbos_version::ARBOS_VERSION_50 {
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
                        internal_tx::encode_batch_posting_report(
                            *batch_timestamp,
                            *batch_poster,
                            *batch_number,
                            input.batch_gas_cost.unwrap_or(0).saturating_add(*extra_gas),
                            *l1_base_fee_estimate,
                        )
                    };
                let report_tx = create_internal_tx(chain_id, &report_data);
                execute_and_commit(&mut executor, &report_tx, "BatchPostingReport")?;
                transactions.push(report_tx);
                continue;
            }
            _ => {}
        }

        let signed = match parsed_tx_to_signed(parsed, chain_id) {
            Some(tx) => tx,
            None => {
                skipped.push(SkippedSequencerTransaction {
                    parsed_index,
                    reason: "parsed transaction has no signed envelope".into(),
                });
                continue;
            }
        };
        let recovered = match signed.clone().try_into_recovered() {
            Ok(recovered) => recovered,
            Err(error) => {
                skipped.push(SkippedSequencerTransaction {
                    parsed_index,
                    reason: format!("sender recovery: {error:?}"),
                });
                continue;
            }
        };

        match executor.execute_transaction_without_commit(recovered) {
            Ok(result) => {
                user_executions.push(SequencerTransactionExecution {
                    transaction: signed.clone(),
                    result: result.result.result.clone(),
                    state: result.result.state.clone(),
                });
                let _ = executor.commit_transaction(result);
                transactions.push(signed);
                drain_scheduled(
                    &mut executor,
                    &mut transactions,
                    &mut user_executions,
                    parsed_index,
                    &mut skipped,
                );
            }
            Err(error) if error.to_string().contains("block gas limit reached") => break,
            Err(error) => skipped.push(SkippedSequencerTransaction {
                parsed_index,
                reason: format!("execution: {error}"),
            }),
        }
    }

    let simulation_progress = executor.simulation_progress();
    let zombie_accounts = executor.zombie_accounts();
    let finalise_deleted = executor.finalise_deleted().clone();
    let (_, execution_result) = executor
        .finish()
        .map_err(|error| SequencerExecutionError::Execution(format!("finish: {error}")))?;

    let read_post_slot = |address: Address, slot: B256| {
        state
            .storage_ref(address, U256::from_be_bytes(slot.0))
            .map(Some)
    };
    let header_info = derive_arb_header_info(&read_post_slot, input.sender)
        .map_err(|error| SequencerExecutionError::State(error.to_string()))?;

    state.merge_transitions(BundleRetention::Reverts);
    let mut bundle = state.take_bundle();
    augment_bundle_from_cache(&mut bundle, &state.cache, &state.database)?;
    apply_account_deletions(
        &mut bundle,
        &zombie_accounts,
        &finalise_deleted,
        &state.database,
    )?;
    filter_unchanged_storage(&mut bundle);

    let (mix_hash, extra_data) = match header_info {
        Some(info) => (
            info.compute_mix_hash(),
            Bytes::copy_from_slice(info.send_root.as_slice()),
        ),
        None => (provisional_mix_hash, parent.extra_data.clone()),
    };

    Ok(ExecutedSequencerBlock {
        state: SequencerBlockState {
            number: l2_block_number,
            hash: input.block_hash,
            timestamp,
            mix_hash,
            beneficiary: input.sender,
            delayed_messages_read: input.delayed_messages_read,
            gas_limit: parent.gas_limit,
            base_fee_per_gas: l2_base_fee,
            extra_data,
        },
        bundle,
        transactions,
        user_executions,
        receipts: execution_result.receipts,
        gas_used: execution_result.gas_used,
        simulation_progress,
        skipped,
    })
}

fn create_internal_tx(chain_id: u64, data: &[u8]) -> ArbTransactionSigned {
    let transaction = ArbTypedTransaction::Internal(ArbInternalTx {
        chain_id: U256::from(chain_id),
        data: Bytes::copy_from_slice(data),
    });
    let signature = alloy_primitives::Signature::new(U256::ZERO, U256::ZERO, false);
    ArbTransactionSigned::new_unhashed(transaction, signature)
}

fn execute_and_commit<E>(
    executor: &mut E,
    transaction: &ArbTransactionSigned,
    label: &str,
) -> Result<(), SequencerExecutionError>
where
    E: BlockExecutor<Transaction = ArbTransactionSigned>,
{
    let recovered = transaction.clone().try_into_recovered().map_err(|error| {
        SequencerExecutionError::Execution(format!("{label} recovery: {error:?}"))
    })?;
    let result = executor
        .execute_transaction_without_commit(recovered)
        .map_err(|error| {
            SequencerExecutionError::Execution(format!("{label} execution: {error}"))
        })?;
    let _ = executor.commit_transaction(result);
    Ok(())
}

fn drain_scheduled<E>(
    executor: &mut E,
    transactions: &mut Vec<ArbTransactionSigned>,
    user_executions: &mut Vec<SequencerTransactionExecution>,
    parsed_index: usize,
    skipped: &mut Vec<SkippedSequencerTransaction>,
) where
    E: BlockExecutor<
            Transaction = ArbTransactionSigned,
            Result = alloy_evm::eth::EthTxResult<
                reth_revm::context::result::HaltReason,
                arb_primitives::ArbTxTypeLocal,
            >,
        > + crate::ArbScheduledTxDrain,
{
    loop {
        let scheduled = executor.drain_scheduled_txs();
        if scheduled.is_empty() {
            return;
        }
        for encoded in scheduled {
            let Some(retry) = ArbTransactionSigned::decode_2718(&mut &encoded[..]).ok() else {
                skipped.push(SkippedSequencerTransaction {
                    parsed_index,
                    reason: "scheduled retryable decode".into(),
                });
                continue;
            };
            let recovered = match retry.clone().try_into_recovered() {
                Ok(recovered) => recovered,
                Err(error) => {
                    skipped.push(SkippedSequencerTransaction {
                        parsed_index,
                        reason: format!("scheduled retryable recovery: {error:?}"),
                    });
                    continue;
                }
            };
            match executor.execute_transaction_without_commit(recovered) {
                Ok(result) => {
                    user_executions.push(SequencerTransactionExecution {
                        transaction: retry.clone(),
                        result: result.result.result.clone(),
                        state: result.result.state.clone(),
                    });
                    let _ = executor.commit_transaction(result);
                    transactions.push(retry);
                }
                Err(error) => skipped.push(SkippedSequencerTransaction {
                    parsed_index,
                    reason: format!("scheduled retryable execution: {error}"),
                }),
            }
        }
    }
}

pub(crate) fn augment_bundle_from_cache<DB>(
    bundle: &mut BundleState,
    cache: &reth_revm::db::CacheState,
    database: &DB,
) -> Result<(), SequencerExecutionError>
where
    DB: DatabaseRef,
    DB::Error: Display,
{
    use reth_revm::db::states::plain_account::StorageSlot;

    for (address, cached) in &cache.accounts {
        let current_info = cached.account.as_ref().map(|account| account.info.clone());
        let current_storage = cached
            .account
            .as_ref()
            .map(|account| &account.storage)
            .cloned()
            .unwrap_or_default();

        if let Some(bundle_account) = bundle.state.get_mut(address) {
            bundle_account.info = current_info;
            for (key, value) in &current_storage {
                if let Some(slot) = bundle_account.storage.get_mut(key) {
                    slot.present_value = *value;
                } else {
                    let original = database
                        .storage_ref(*address, *key)
                        .map_err(|error| SequencerExecutionError::State(error.to_string()))?;
                    if *value != original {
                        bundle_account.storage.insert(
                            *key,
                            StorageSlot {
                                previous_or_original_value: original,
                                present_value: *value,
                            },
                        );
                    }
                }
            }
            continue;
        }

        let original_info = database
            .basic_ref(*address)
            .map_err(|error| SequencerExecutionError::State(error.to_string()))?;
        let info_changed = current_info != original_info;
        let mut storage = alloy_primitives::map::U256Map::default();
        for (key, value) in &current_storage {
            let original = database
                .storage_ref(*address, *key)
                .map_err(|error| SequencerExecutionError::State(error.to_string()))?;
            if original != *value {
                storage.insert(
                    *key,
                    StorageSlot {
                        previous_or_original_value: original,
                        present_value: *value,
                    },
                );
            }
        }
        if info_changed || !storage.is_empty() {
            bundle.state.insert(
                *address,
                reth_revm::db::BundleAccount {
                    info: current_info,
                    original_info: original_info.clone(),
                    storage,
                    status: if original_info.is_some() {
                        BundleAccountStatus::Changed
                    } else {
                        BundleAccountStatus::InMemoryChange
                    },
                },
            );
        }
    }
    Ok(())
}

pub(crate) fn apply_account_deletions<DB>(
    bundle: &mut BundleState,
    zombie_accounts: &rustc_hash::FxHashSet<Address>,
    finalise_deleted: &rustc_hash::FxHashSet<Address>,
    database: &DB,
) -> Result<(), SequencerExecutionError>
where
    DB: DatabaseRef,
    DB::Error: Display,
{
    let empty_hash = alloy_primitives::KECCAK256_EMPTY;
    for address in finalise_deleted {
        if zombie_accounts.contains(address) {
            continue;
        }
        if let Some(account) = bundle.state.get_mut(address) {
            let still_empty = account.info.as_ref().is_none_or(|info| {
                info.nonce == 0 && info.balance.is_zero() && info.code_hash == empty_hash
            });
            if still_empty {
                if account.original_info.is_some() {
                    account.info = None;
                } else {
                    bundle.state.remove(address);
                }
            }
            continue;
        }
        if let Some(original) = database
            .basic_ref(*address)
            .map_err(|error| SequencerExecutionError::State(error.to_string()))?
        {
            if original.nonce != 0
                || !original.balance.is_zero()
                || original.code_hash != empty_hash
            {
                bundle.state.insert(
                    *address,
                    reth_revm::db::BundleAccount {
                        info: None,
                        original_info: Some(original),
                        storage: Default::default(),
                        status: BundleAccountStatus::Changed,
                    },
                );
            }
        }
    }

    let mut remove = Vec::new();
    for (address, account) in &mut bundle.state {
        let Some(info) = &account.info else {
            continue;
        };
        if info.nonce != 0 || !info.balance.is_zero() || info.code_hash != empty_hash {
            continue;
        }
        if zombie_accounts.contains(address) {
            continue;
        }
        if database
            .basic_ref(*address)
            .map_err(|error| SequencerExecutionError::State(error.to_string()))?
            .is_some()
        {
            account.info = None;
        } else {
            remove.push(*address);
        }
    }
    for address in remove {
        bundle.state.remove(&address);
    }
    Ok(())
}

pub(crate) fn filter_unchanged_storage(bundle: &mut BundleState) {
    for account in bundle.state.values_mut() {
        account
            .storage
            .retain(|_, slot| slot.present_value != slot.previous_or_original_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arb_storage::ARBOS_STATE_ADDRESS;
    use arbos::{arbos_state::initialize::bootstrap, burn::SystemBurner};
    use reth_revm::state::AccountInfo;
    use std::sync::Arc;

    #[test]
    fn rejects_a_non_contiguous_sequence_before_touching_the_database() {
        let config = ArbEvmConfig::new(Arc::new(ChainSpec::default()));
        let parent = SequencerBlockState {
            number: 41,
            hash: B256::repeat_byte(1),
            timestamp: 10,
            mix_hash: arbos::header::compute_arbos_mixhash(0, 5, 61, false),
            beneficiary: Address::ZERO,
            delayed_messages_read: 0,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1),
            extra_data: Bytes::new(),
        };
        let input = SequencerBlockInput {
            sequence_number: 44,
            block_hash: B256::repeat_byte(2),
            kind: 6,
            sender: Address::ZERO,
            l1_block_number: 5,
            l1_timestamp: 11,
            request_id: None,
            l1_base_fee: None,
            l2_msg: Vec::new(),
            delayed_messages_read: 0,
            batch_gas_cost: None,
            batch_data_stats: None,
        };
        let error =
            execute_sequencer_block(&config, reth_revm::db::EmptyDB::default(), &parent, &input)
                .unwrap_err();
        assert!(matches!(
            error,
            SequencerExecutionError::Continuity {
                expected: 42,
                actual: 44
            }
        ));
    }

    #[test]
    fn executes_empty_v61_message_through_start_block_and_returns_one_bundle() {
        let mut parent_db = StateBuilder::new()
            .with_database(reth_revm::db::CacheDB::new(
                reth_revm::db::EmptyDB::default(),
            ))
            .with_bundle_update()
            .build();
        parent_db.insert_account(ARBOS_STATE_ADDRESS, AccountInfo::default());
        bootstrap(
            &mut parent_db,
            4663,
            Address::ZERO,
            Address::ZERO,
            U256::from(100_000_000u64),
            61,
            SystemBurner::new(None, false),
        )
        .unwrap();
        parent_db.merge_transitions(BundleRetention::PlainState);

        let config = ArbEvmConfig::new(Arc::new(ChainSpec::default()));
        let parent = SequencerBlockState {
            number: 0,
            hash: B256::repeat_byte(1),
            timestamp: 10,
            mix_hash: arbos::header::compute_arbos_mixhash(0, 5, 61, false),
            beneficiary: Address::ZERO,
            delayed_messages_read: 0,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(100_000_000),
            extra_data: Bytes::from(vec![0; 32]),
        };
        let input = SequencerBlockInput {
            sequence_number: 1,
            block_hash: B256::repeat_byte(2),
            kind: 6,
            sender: Address::ZERO,
            l1_block_number: 6,
            l1_timestamp: 11,
            request_id: None,
            l1_base_fee: Some(U256::from(1_000_000_000u64)),
            l2_msg: Vec::new(),
            delayed_messages_read: 0,
            batch_gas_cost: None,
            batch_data_stats: None,
        };

        let output = execute_sequencer_block(&config, parent_db, &parent, &input).unwrap();
        assert_eq!(output.state.number, 1);
        assert_eq!(output.state.hash, input.block_hash);
        assert_eq!(output.state.timestamp, 11);
        assert_eq!(
            extract_arbos_version_from_mix_hash(output.state.mix_hash),
            61
        );
        assert_eq!(output.transactions.len(), 1, "StartBlock only");
        assert!(output.skipped.is_empty());
        assert!(!output.bundle.state.is_empty());
    }

    #[test]
    fn fresh_direct_epoch_populates_full_arb_block_hash_window_from_database() {
        // Model a pinned MDBX anchor plus hashes retained while applying a UDS
        // or direct suffix. A freshly-created ArbEvmConfig must cold-populate
        // both near and deep ancestors before executing its first message.
        let mut cache = reth_revm::db::CacheDB::new(reth_revm::db::EmptyDB::default());
        for number in 45..=299u64 {
            cache.cache.block_hashes.insert(
                U256::from(number),
                B256::from(U256::from(number).to_be_bytes::<32>()),
            );
        }
        let mut parent_db = StateBuilder::new()
            .with_database(cache)
            .with_bundle_update()
            .build();
        parent_db.insert_account(ARBOS_STATE_ADDRESS, AccountInfo::default());
        bootstrap(
            &mut parent_db,
            4663,
            Address::ZERO,
            Address::ZERO,
            U256::from(100_000_000u64),
            61,
            SystemBurner::new(None, false),
        )
        .unwrap();
        parent_db.merge_transitions(BundleRetention::PlainState);

        let config = ArbEvmConfig::new(Arc::new(ChainSpec::default()));
        let parent = SequencerBlockState {
            number: 300,
            hash: B256::repeat_byte(0x30),
            timestamp: 10,
            mix_hash: arbos::header::compute_arbos_mixhash(0, 5, 61, false),
            beneficiary: Address::ZERO,
            delayed_messages_read: 0,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(100_000_000),
            extra_data: Bytes::from(vec![0; 32]),
        };
        let input = SequencerBlockInput {
            sequence_number: 301,
            block_hash: B256::repeat_byte(0x31),
            kind: 6,
            sender: Address::ZERO,
            l1_block_number: 6,
            l1_timestamp: 11,
            request_id: None,
            l1_base_fee: Some(U256::from(1_000_000_000u64)),
            l2_msg: Vec::new(),
            delayed_messages_read: 0,
            batch_gas_cost: None,
            batch_data_stats: None,
        };

        execute_sequencer_block(&config, parent_db, &parent, &input).unwrap();
        let hashes = config
            .executor_factory
            .arb_evm_factory()
            .chain_caches()
            .l2_block_hashes
            .lock();
        assert_eq!(hashes.get(&300), Some(&parent.hash));
        for number in [299u64, 46] {
            assert_eq!(
                hashes.get(&number),
                Some(&B256::from(U256::from(number).to_be_bytes::<32>())),
                "missing ancestor {number} from fresh direct epoch"
            );
        }
    }
}

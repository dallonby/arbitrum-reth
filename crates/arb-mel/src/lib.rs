//! arb-mel

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_consensus::{Header, Transaction};
use alloy_primitives::{Address, B256, Log, keccak256};
use arbos::arbos_types::MessageWithMetadata;

#[derive(Debug, thiserror::Error)]
pub enum MelError {
    #[error("parent chain block hash mismatch: expected {expected}, got {got}")]
    ParentHashMismatch { expected: B256, got: B256 },

    #[error("batch posting reports {reports} exceed batches {batches}")]
    TooManyBatchPostingReports { reports: usize, batches: usize },

    #[error(transparent)]
    Storage(#[from] arb_storage_errors::StorageError),

    #[error("unknown error")]
    Unknown,
}

pub type MelResult<T> = Result<T, MelError>;

#[derive(Default, Clone)]
pub struct MelState {
    pub parent_chain_block_hash: B256,
    pub parent_chain_prev_block_hash: B256,
    pub parent_chain_block_number: u64,
    pub batch_count: u64,
    pub msg_count: u64,
    pub delayed_messages_seen: u64,
    pub delayed_messages_read: u64,
    pub delayed_message_posting_target_address: Address,
    pub batch_posting_target_address: Address,
    pub version: u16,
}

impl MelState {
    pub fn accumulate_delayed_message(&mut self, _message: &DelayedInboxMessage) -> MelResult<()> {
        Ok(())
    }
    pub fn accumulate_message(&mut self, _message: &MessageWithMetadata) -> MelResult<()> {
        Ok(())
    }
    pub fn move_unread_delayed_messages_to_inbox_accumulator(
        &mut self,
        _delayed_msg_db: &impl DelayedMessageDB,
    ) -> MelResult<()> {
        Ok(())
    }
}

pub struct DelayedInboxMessage;

pub trait LogsFetcher {
    fn logs_for_block_hash(&self, block_hash: B256) -> Result<Vec<Log>, MelError>;
    fn logs_for_tx_index(&self, block_hash: B256, tx_index: u64) -> Result<Vec<Log>, MelError>;
}

pub trait TxFetcher {}

pub trait DelayedMessageDB {
    fn read_delayed_message(&self, mel_state: &MelState, index: u64) 
        -> MelResult<DelayedInboxMessage>;
}

pub struct ExtractionOutput {
    pub post_state: MelState,
    pub messages: Vec<MessageWithMetadata>,
    pub delayed_messages: Vec<DelayedInboxMessage>,
    pub batch_metas: Vec<BatchMeta>,
}

pub struct Batch {
    pub sequence_number: u64,
    pub after_delayed_count: u64,
}

pub struct BatchMeta {
}

pub fn extract_messages<D, L, T>(
    input_state: &MelState,
    parent_chain_header: &Header,
    delayed_msg_db: &D,
    logs_fetcher: &L,
    tx_fetcher: &T,
) -> MelResult<ExtractionOutput>
where
    D: DelayedMessageDB,
    L: LogsFetcher,
    T: TxFetcher,
{
    // Verify parent chain header linkage.
    if input_state.parent_chain_block_hash != parent_chain_header.parent_hash {
        return Err(MelError::ParentHashMismatch {
            expected: input_state.parent_chain_block_hash,
            got: parent_chain_header.hash_slow(),
        });
    }
    let mut post_state = input_state.clone();
    post_state.parent_chain_block_hash = parent_chain_header.hash_slow();
    post_state.parent_chain_prev_block_hash = input_state.parent_chain_block_hash;
    post_state.parent_chain_block_number = parent_chain_header.number;

    let (batches, batch_txs) = lookup_batches()?;
    let delayed_messages = lookup_delayed_messages()?;

    let mut batch_posting_reports: Vec<&DelayedInboxMessage> = vec![];
    for delayed in delayed_messages.iter() {
        // TODO: Check if it is a batch posting report instead.
        if true {
            batch_posting_reports.push(delayed);
        }
    }
    if batch_posting_reports.len() > batches.len() {
        return Err(MelError::TooManyBatchPostingReports { 
            reports: batch_posting_reports.len(), 
            batches: batches.len(),
        });
    }

    let mut batch_post_report_idx: usize = 0;
    let mut batch_post_report_batch_hash = B256::ZERO;
    let mut messages: Vec<MessageWithMetadata> = Vec::new();
    let mut serialized_batches: Vec<Vec<u8>> = Vec::new();
    for (i, batch) in batches.iter().enumerate() {
        let serialized = serialize_batch(batch, logs_fetcher)?;
        if batch_post_report_idx < batch_posting_reports.len() {
            let report = batch_posting_reports[batch_post_report_idx];
            if batch_post_report_batch_hash == B256::ZERO {
            }
            let got_hash = keccak256(&serialized);
            if got_hash == batch_post_report_batch_hash {
                // Fill in the gas stats.
                // Process next report.
                batch_post_report_idx += 1;
                batch_post_report_batch_hash = B256::ZERO;
            }
        }
        serialized_batches.push(serialized);
    }

    if batch_posting_reports.len() != batch_post_report_idx {
        return Err(MelError::TooManyBatchPostingReports { 
            reports: batch_posting_reports.len(), 
            batches: batches.len(),
        });
    }

    // Update the delayed message inbox accumulator in the MelState.
    for delayed in delayed_messages.iter() {
        post_state.accumulate_delayed_message(delayed)?;
        post_state.delayed_messages_seen += 1;
    }

    let mut messages = Vec::new();
    let mut batch_metas = Vec::new();

    // Extract L2 messages from batches.
    for (i, batch) in batches.iter().enumerate() {
        let expected_batch_seq_num = batches[0].sequence_number + i as u64;
        if batch.sequence_number != expected_batch_seq_num {
            // This should never happen if the batch fetching logic is correct.
            return Err(MelError::Unknown);
            // return Err(MelError::Storage(arb_storage_errors::StorageError::DataCorruption(format!(
            //     "Batch sequence number mismatch: expected {}, got {}",
            //     expected_batch_seq_num, batch.sequence_number
            // ))));
        }
        let serialized = &serialized_batches[i];
        let raw_seq_msg = parse_sequencer_message()?;
        let messages_in_batch = extract_batch_messages()?;
        for msg in messages_in_batch.into_iter() {
            post_state.accumulate_message(&msg)?;
            messages.push(msg);
            post_state.msg_count += 1;
        }
        post_state.batch_count += 1;
        batch_metas.push(BatchMeta {
        });
        if batch.after_delayed_count != post_state.delayed_messages_read {
            return Err(MelError::Unknown);
        }
    }

    // Check for MEL config events in this block.
    if let Some(mel_config) = lookup_mel_config()? {
        // Sanity check: the contract sets activation block = block.number at emission.
        // This means the event must be observed in the same parent chain block
        // it was emitted in.
        if mel_config.activation_block != parent_chain_header.number {
            return Err(MelError::Unknown);
        }
        if post_state.version == 0 {
            post_state.move_unread_delayed_messages_to_inbox_accumulator(delayed_msg_db)?;
        }
        post_state.version = mel_config.mel_version;
        post_state.delayed_message_posting_target_address = mel_config.inbox;
        post_state.batch_posting_target_address = mel_config.sequencer_inbox;
    }

    Ok(ExtractionOutput { 
        post_state,
        messages,
        delayed_messages,
        batch_metas,
    })
}

#[derive(Default)]
struct MelConfig {
    pub activation_block: u64,
    pub mel_version: u16,
    pub inbox: Address,
    pub sequencer_inbox: Address,
}

fn lookup_batches() -> MelResult<(Vec<Batch>, Vec<Batch>)> {
    Ok((Vec::new(), Vec::new()))
}

fn lookup_delayed_messages() -> MelResult<Vec<DelayedInboxMessage>> {
    Ok(Vec::new())
}

fn serialize_batch(
    batch: &Batch,
    logs_fetcher: &impl LogsFetcher,
) -> MelResult<Vec<u8>> {
    Ok(Vec::new())
}

fn extract_batch_messages() -> MelResult<Vec<MessageWithMetadata>> {
    Ok(Vec::new())
}

fn parse_sequencer_message() -> MelResult<u8> {
    Ok(9)
}

fn lookup_mel_config() -> MelResult<Option<MelConfig>> {
    Ok(Some(MelConfig::default()))
}

#[cfg(test)]
mod test {
    #[test]
    fn test_extract_messages() {
        // Placeholder test
        assert_eq!(2 + 2, 4);
    }
}
use alloy_primitives::{keccak256, B256, U256};
use revm::Database;

use arb_storage::{Storage, StorageBackedUint64, StorageBackend, SystemStateBackend};

mod error;
pub use error::BlockhashesError;

pub struct Blockhashes<'a, D> {
    backing_storage: Storage<'a, D>,
    l1_block_number: StorageBackedUint64,
}

pub fn initialize_blockhashes<D: Database>(_backing_storage: &Storage<'_, D>) {
    // no-op: next_block_number is already zero
}

pub fn open_blockhashes<D>(backing_storage: Storage<'_, D>) -> Blockhashes<'_, D> {
    let l1_block_number = StorageBackedUint64::new(backing_storage.base_key(), 0);
    Blockhashes {
        backing_storage,
        l1_block_number,
    }
}

impl<D> Blockhashes<'_, D> {
    pub fn l1_block_number<B: SystemStateBackend>(
        &self,
        backend: &mut B,
    ) -> Result<u64, BlockhashesError> {
        Ok(self.l1_block_number.get(backend)?)
    }

    pub fn block_hash<B: SystemStateBackend>(
        &self,
        backend: &mut B,
        number: u64,
    ) -> Result<Option<B256>, BlockhashesError> {
        let current_number = self.l1_block_number.get(backend)?;
        if number >= current_number || number + 256 < current_number {
            return Ok(None);
        }
        let slot = self.backing_storage.new_slot(1 + (number % 256));
        let hash = backend
            .sload_system(self.backing_storage.account(), slot)
            .map_err(Into::into)?;
        Ok(Some(B256::from(hash)))
    }

    pub fn record_new_l1_block<B: StorageBackend>(
        &self,
        backend: &mut B,
        number: u64,
        block_hash: B256,
        arbos_version: u64,
    ) -> Result<(), BlockhashesError> {
        let mut next_number = self.l1_block_number.get(backend)?;

        if number < next_number {
            return Ok(());
        }

        if next_number + 256 < number {
            next_number = number - 256;
        }

        while next_number + 1 < number {
            next_number += 1;

            let mut next_num_buf = [0u8; 8];
            if arbos_version >= 8 {
                next_num_buf.copy_from_slice(&next_number.to_le_bytes());
            }

            let mut combined = Vec::with_capacity(40);
            combined.extend_from_slice(block_hash.as_slice());
            combined.extend_from_slice(&next_num_buf);
            let fill = keccak256(&combined);

            let slot = self.backing_storage.new_slot(1 + (next_number % 256));
            backend
                .sstore(
                    self.backing_storage.account(),
                    slot,
                    U256::from_be_bytes(fill.0),
                )
                .map_err(Into::into)?;
        }

        let slot = self.backing_storage.new_slot(1 + (number % 256));
        backend
            .sstore(
                self.backing_storage.account(),
                slot,
                U256::from_be_bytes(block_hash.0),
            )
            .map_err(Into::into)?;
        Ok(self.l1_block_number.set(backend, number + 1)?)
    }
}

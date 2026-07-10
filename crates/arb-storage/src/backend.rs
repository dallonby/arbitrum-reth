use alloy_primitives::{map::AddressMap, Address, Bytes, U256};
use arb_storage_errors::{DatabaseError, StorageError};
use revm::{Database, DatabaseCommit};

use crate::{
    state_ops::{read_storage_at, write_storage_at},
    storage::Storage,
};

/// Abstraction over the two backing stores `arb-storage` accessor types are
/// driven from: the block executor's `&mut State<D>` and the precompile
/// handler's `&mut EvmInternals<'_>`.
///
/// The trait sits beneath the typed accessor layer (`StorageBackedX`) so the
/// same descriptors serve both call paths without having to fork the
/// accessor API.
pub trait StorageBackend: SystemStateBackend {
    /// Reads the value at `(account, slot)`. Reads through `StorageBackend`
    /// follow the host's normal storage path (journaled when invoked on
    /// `EvmInternals`); for non-journaled reads see [`SystemStateBackend`].
    fn sload(
        &mut self,
        account: Address,
        slot: U256,
    ) -> Result<U256, <Self as SystemStateBackend>::Error>;

    /// Writes `value` to `(account, slot)`.
    fn sstore(
        &mut self,
        account: Address,
        slot: U256,
        value: U256,
    ) -> Result<(), <Self as SystemStateBackend>::Error>;
}

/// Non-journaled read access to system state.
///
/// Reads bypass the EVM journal: no access-list entry, no cold/warm gas
/// tracking, no account-touch propagation. Use for ArbOS state and other
/// system reads with no consensus relationship to user-visible EVM storage.
///
/// Writes are NOT in this trait. System-state mutations that happen inside
/// a user-callable precompile must remain journaled so they revert with
/// the outer tx on failure (matching geth's StateDB semantics).
/// Writes stay on [`StorageBackend`].
pub trait SystemStateBackend {
    /// Concrete failure type produced by the backend. Convertible into
    /// [`StorageError`] so callers can stay uniform.
    type Error: Into<StorageError>;

    /// Reads the value at `(account, slot)` without journaling.
    fn sload_system(&mut self, account: Address, slot: U256) -> Result<U256, Self::Error>;
}

/// Account-level system mutations needed by ArbOS version migrations.
pub trait AccountStateBackend: StorageBackend {
    fn account_balance(&mut self, account: Address) -> Result<U256, Self::Error>;
    fn set_account_nonce(&mut self, account: Address, nonce: u64) -> Result<(), Self::Error>;
    fn set_account_code(&mut self, account: Address, code: Bytes) -> Result<(), Self::Error>;
}

// Keep the concrete revm State usable by tests, genesis helpers, and offline
// tools. Production block execution is generic over StateDB and therefore
// uses `StateDbBackend`; these implementations retain the transition-aware
// cache/bundle behaviour of the original concrete path.
impl<D: Database> StorageBackend for revm::database::State<D> {
    fn sload(&mut self, account: Address, slot: U256) -> Result<U256, StorageError> {
        read_storage_at(self, account, slot)
    }

    fn sstore(&mut self, account: Address, slot: U256, value: U256) -> Result<(), StorageError> {
        write_storage_at(self, account, slot, value)
    }
}

impl<D: Database> SystemStateBackend for revm::database::State<D> {
    type Error = StorageError;

    fn sload_system(&mut self, account: Address, slot: U256) -> Result<U256, Self::Error> {
        read_storage_at(self, account, slot)
    }
}

impl<D: Database> AccountStateBackend for revm::database::State<D> {
    fn account_balance(&mut self, account: Address) -> Result<U256, Self::Error> {
        Ok(crate::state_ops::get_account_balance(self, account))
    }

    fn set_account_nonce(&mut self, account: Address, nonce: u64) -> Result<(), Self::Error> {
        crate::state_ops::set_account_nonce(self, account, nonce);
        Ok(())
    }

    fn set_account_code(&mut self, account: Address, code: Bytes) -> Result<(), Self::Error> {
        crate::state_ops::set_account_code(self, account, code);
        Ok(())
    }
}

/// Transparent adapter for the generic executor state used by Alloy EVM 0.36
/// and newer.
///
/// Reth 2.3 deliberately exposes only the `Database + DatabaseCommit`
/// contract to block executors. Reads therefore go through `Database`, while
/// each system write is represented as a touched revm account and committed
/// through the same path as normal EVM output. This keeps the implementation
/// valid for `State<DB>`, BAL-aware databases, and diagnostic overlay DBs.
///
/// A newtype is necessary rather than a blanket `StorageBackend for D` impl:
/// the precompile-side `EvmInternals` has intentionally different journaled
/// semantics, and Rust coherence must keep that implementation disjoint.
#[repr(transparent)]
#[derive(Debug)]
pub struct StateDbBackend<D: ?Sized>(D);

impl<D: ?Sized> StateDbBackend<D> {
    /// Reborrow a StateDB as its transparent ArbOS backend adapter.
    pub fn from_mut(db: &mut D) -> &mut Self {
        // SAFETY: `StateDbBackend<D>` is repr(transparent) over `D` and adds no
        // fields, so the pointer metadata and layout are identical.
        unsafe { &mut *(db as *mut D as *mut Self) }
    }

    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.0
    }
}

impl<D: Database + ?Sized> Database for StateDbBackend<D> {
    type Error = D::Error;

    fn basic(&mut self, address: Address) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        self.0.basic(address)
    }

    fn code_by_hash(
        &mut self,
        code_hash: alloy_primitives::B256,
    ) -> Result<revm::state::Bytecode, Self::Error> {
        self.0.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.0.storage(address, index)
    }

    fn storage_by_account_id(
        &mut self,
        address: Address,
        account_id: revm::state::AccountId,
        storage_key: U256,
    ) -> Result<U256, Self::Error> {
        self.0
            .storage_by_account_id(address, account_id, storage_key)
    }

    fn block_hash(&mut self, number: u64) -> Result<alloy_primitives::B256, Self::Error> {
        self.0.block_hash(number)
    }
}

impl<D: DatabaseCommit + ?Sized> DatabaseCommit for StateDbBackend<D> {
    fn commit(&mut self, changes: AddressMap<revm::state::Account>) {
        self.0.commit(changes);
    }

    fn commit_iter(&mut self, changes: &mut dyn Iterator<Item = (Address, revm::state::Account)>) {
        self.0.commit_iter(changes);
    }
}

impl<D> StorageBackend for StateDbBackend<D>
where
    D: Database + DatabaseCommit,
{
    fn sload(&mut self, account: Address, slot: U256) -> Result<U256, StorageError> {
        self.storage(account, slot)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }

    fn sstore(&mut self, account: Address, slot: U256, value: U256) -> Result<(), StorageError> {
        use revm::state::{Account, EvmStorageSlot, TransactionId};

        let current = self
            .storage(account, slot)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))?;
        if current == value {
            return Ok(());
        }

        let info = self
            .basic(account)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))?;
        let mut changed = match info {
            Some(info) => Account::from(info),
            None => {
                let mut account = Account::new_not_existing(TransactionId::ZERO);
                account.mark_created();
                account
            }
        };
        changed.storage.insert(
            slot,
            EvmStorageSlot::new_changed(current, value, TransactionId::ZERO),
        );
        changed.mark_touch();

        let mut changes = AddressMap::default();
        changes.insert(account, changed);
        self.commit(changes);
        Ok(())
    }
}

impl<D> SystemStateBackend for StateDbBackend<D>
where
    D: Database + DatabaseCommit,
{
    type Error = StorageError;

    fn sload_system(&mut self, account: Address, slot: U256) -> Result<U256, Self::Error> {
        self.storage(account, slot)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }
}

impl<D> AccountStateBackend for StateDbBackend<D>
where
    D: Database + DatabaseCommit,
{
    fn account_balance(&mut self, account: Address) -> Result<U256, Self::Error> {
        self.basic(account)
            .map(|info| info.map_or(U256::ZERO, |info| info.balance))
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }

    fn set_account_nonce(&mut self, account: Address, nonce: u64) -> Result<(), Self::Error> {
        self.commit_account_info_change(account, |info| info.nonce = nonce)
    }

    fn set_account_code(&mut self, account: Address, code: Bytes) -> Result<(), Self::Error> {
        self.commit_account_info_change(account, |info| {
            let code = revm::state::Bytecode::new_raw(code);
            info.code_hash = code.hash_slow();
            info.code = Some(code);
        })
    }
}

impl<D> StateDbBackend<D>
where
    D: Database + DatabaseCommit,
{
    fn commit_account_info_change(
        &mut self,
        address: Address,
        change: impl FnOnce(&mut revm::state::AccountInfo),
    ) -> Result<(), StorageError> {
        use revm::state::{Account, TransactionId};

        let current = self
            .basic(address)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))?;
        let mut account = match current {
            Some(info) => Account::from(info),
            None => {
                let mut account = Account::new_not_existing(TransactionId::ZERO);
                account.mark_created();
                account
            }
        };
        change(&mut account.info);
        account.mark_touch();
        let mut changes = AddressMap::default();
        changes.insert(address, account);
        self.commit(changes);
        Ok(())
    }
}

impl StorageBackend for alloy_evm::EvmInternals<'_> {
    fn sload(&mut self, account: Address, slot: U256) -> Result<U256, StorageError> {
        alloy_evm::EvmInternals::sload(self, account, slot)
            .map(|state_load| state_load.data)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }

    fn sstore(&mut self, account: Address, slot: U256, value: U256) -> Result<(), StorageError> {
        alloy_evm::EvmInternals::sstore(self, account, slot, value)
            .map(|_| ())
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }
}

impl AccountStateBackend for alloy_evm::EvmInternals<'_> {
    fn account_balance(&mut self, account: Address) -> Result<U256, Self::Error> {
        self.load_account(account)
            .map(|load| load.data.info.balance)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }

    fn set_account_nonce(&mut self, account: Address, nonce: u64) -> Result<(), Self::Error> {
        self.load_account_mut(account)
            .map(|mut load| load.data.set_nonce(nonce))
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }

    fn set_account_code(&mut self, account: Address, code: Bytes) -> Result<(), Self::Error> {
        alloy_evm::EvmInternals::set_code(self, account, revm::state::Bytecode::new_raw(code))
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }
}

impl SystemStateBackend for alloy_evm::EvmInternals<'_> {
    type Error = StorageError;

    fn sload_system(&mut self, account: Address, slot: U256) -> Result<U256, Self::Error> {
        // Reads route through the journal so that in-flight writes within the
        // current tx are observed, matching geth-StateDB semantics. The
        // journal's access-list bookkeeping is unavoidable on this path; the
        // perf win comes from the per-block ArbosState cache reusing the
        // descriptor across calls instead of reconstructing it.
        alloy_evm::EvmInternals::sload(self, account, slot)
            .map(|state_load| state_load.data)
            .map_err(|e| StorageError::Database(DatabaseError::custom(e)))
    }
}

impl<D: Database> StorageBackend for Storage<'_, D> {
    fn sload(&mut self, account: Address, slot: U256) -> Result<U256, StorageError> {
        // SAFETY: see `Storage` struct-level invariant.
        let state = unsafe { self.state_mut() };
        read_storage_at(state, account, slot)
    }

    fn sstore(&mut self, account: Address, slot: U256, value: U256) -> Result<(), StorageError> {
        // SAFETY: see `Storage` struct-level invariant.
        let state = unsafe { self.state_mut() };
        write_storage_at(state, account, slot, value)
    }
}

impl<D: Database> SystemStateBackend for Storage<'_, D> {
    type Error = StorageError;

    fn sload_system(&mut self, account: Address, slot: U256) -> Result<U256, Self::Error> {
        // SAFETY: see `Storage` struct-level invariant.
        let state = unsafe { self.state_mut() };
        read_storage_at(state, account, slot)
    }
}

//! Arbitrum EVM execution layer.
//!
//! Block executor, custom opcode handlers, EVM configuration, and receipt
//! building for Arbitrum's modified execution environment.

extern crate alloc;

pub mod assembler;
pub mod build;
pub mod config;
pub mod context;
pub mod evm;
pub mod executor;
pub mod hooks;
pub mod multi_gas;
pub mod receipt;
pub mod sequencer;
pub mod simulation;
pub mod state_overlay;
pub mod transaction;

pub use assembler::ArbBlockAssembler;
pub use build::{
    ArbBlockExecutor, ArbBlockExecutorFactory, ArbScheduledTxDrain, ArbSimulationProgress,
    ArbTransactionEnv,
};
pub use config::ArbEvmConfig;
pub use context::{
    ActivatedWasm, ArbBlockExecutionCtx, ArbNextBlockEnvCtx, ArbitrumExtraData,
    InconsistentWasmTargets, RecentWasms,
};
pub use evm::{ArbEvm, ArbEvmFactory};
pub use executor::DefaultArbOsHooks;
pub use hooks::{ArbOsHooks, NoopArbOsHooks};
pub use receipt::ArbReceiptBuilder;
pub use sequencer::{
    execute_sequencer_block, prewarm_sequencer_recovery_pool, ExecutedSequencerBlock,
    SequencerBlockInput, SequencerBlockState, SequencerExecutionTiming,
    SequencerTransactionExecution, SequencerTransactionFailureStage,
};
pub use simulation::{
    execute_simulated_batch, execute_simulated_batch_with_inspector,
    execute_simulated_signed_block, execute_simulated_transaction,
    execute_simulated_transaction_with_inspector, ArbSimulationBatchOutput,
    ArbSimulationBlockStart, ArbSimulationError, ArbSimulationOutput, ArbSimulationTransaction,
    ArbSimulationTransactionOutput, ArbSimulationValidation,
};
pub use transaction::ArbTransaction;

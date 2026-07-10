use std::sync::Arc;

use alloy_consensus::Header;
use arb_node::{
    args::{RollupArgs, StateRootAlgorithm},
    consensus::ArbConsensus,
};
use clap::Parser;
use reth_chainspec::ChainSpec;
use reth_consensus::HeaderValidator;
use reth_primitives_traits::SealedHeader;

#[derive(Parser, Debug)]
struct TestCli {
    #[command(flatten)]
    rollup: RollupArgs,
}

#[test]
fn rollup_args_defaults_to_non_sequencer() {
    let args: RollupArgs = RollupArgs::default();
    assert!(!args.sequencer);
}

#[test]
fn rollup_args_parses_sequencer_flag() {
    let cli = TestCli::try_parse_from(["test", "--rollup.sequencer"]).expect("parse");
    assert!(cli.rollup.sequencer);
}

#[test]
fn rollup_args_omit_sequencer_stays_false() {
    let cli = TestCli::try_parse_from(["test"]).expect("parse");
    assert!(!cli.rollup.sequencer);
}

#[test]
fn rollup_args_invalid_flag_errors() {
    assert!(TestCli::try_parse_from(["test", "--rollup.unknown"]).is_err());
}

#[test]
fn state_root_args_default_to_canonical_parallel() {
    let args = RollupArgs::default();
    assert!(!args.skip_state_root_validation);
    assert_eq!(args.state_root_algorithm, StateRootAlgorithm::Parallel);
    assert_eq!(args.state_root_verify_every, 0);
}

#[test]
fn state_root_fast_mode_and_verifier_parse() {
    let cli = TestCli::try_parse_from([
        "test",
        "--engine.skip-state-root-validation",
        "--engine.state-root-algorithm",
        "serial",
        "--engine.state-root-verify-every",
        "128",
    ])
    .expect("parse state-root options");
    assert!(cli.rollup.skip_state_root_validation);
    assert_eq!(cli.rollup.state_root_algorithm, StateRootAlgorithm::Serial);
    assert_eq!(cli.rollup.state_root_verify_every, 128);
}

// ==== ArbConsensus (no-op, always Ok) ====

fn mk_spec() -> Arc<ChainSpec> {
    Arc::new(ChainSpec::default())
}

#[test]
fn consensus_header_validates_always() {
    let c: ArbConsensus<ChainSpec> = ArbConsensus::new(mk_spec());
    let header = Header::default();
    let sealed = SealedHeader::seal_slow(header);
    assert!(HeaderValidator::validate_header(&c, &sealed).is_ok());
}

#[test]
fn consensus_header_against_parent_validates_always() {
    let c: ArbConsensus<ChainSpec> = ArbConsensus::new(mk_spec());
    let h1 = SealedHeader::seal_slow(Header::default());
    let h2 = SealedHeader::seal_slow(Header::default());
    assert!(HeaderValidator::validate_header_against_parent(&c, &h1, &h2).is_ok());
}

#[test]
fn consensus_is_debug_and_clone_and_eq() {
    let c1: ArbConsensus<ChainSpec> = ArbConsensus::new(mk_spec());
    let c2 = c1.clone();
    assert_eq!(c1, c2);
    let _s = format!("{c1:?}");
}

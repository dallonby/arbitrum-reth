use alloy_primitives::U256;
use arb_primitives::multigas::{ResourceKind, NUM_RESOURCE_KIND};
use arb_test_utils::ArbosHarness;

const ARBOS_V30: u64 = 30;
const ARBOS_V60: u64 = 60;
const ARBOS_V61: u64 = 61;

fn weights(pairs: &[(ResourceKind, u64)]) -> [u64; NUM_RESOURCE_KIND] {
    let mut out = [0u64; NUM_RESOURCE_KIND];
    for &(kind, w) in pairs {
        out[kind as usize] = w;
    }
    out
}

#[test]
fn legacy_pricing_model_steady_state_and_escalation() {
    let mut h = ArbosHarness::new()
        .with_arbos_version(ARBOS_V30)
        .initialize();
    let state_ptr = h.state_ptr();
    let p = h.l2_pricing_state();
    let b = unsafe { &mut *state_ptr };

    let min_price = p.min_base_fee_wei(b).unwrap();
    let limit = p.speed_limit_per_second(b).unwrap();
    assert_eq!(p.base_fee_wei(b).unwrap(), min_price);

    for seconds in 0u64..4 {
        let prev = p.gas_backlog(b).unwrap();
        p.set_gas_backlog(b, prev.saturating_add(seconds.saturating_mul(limit)))
            .unwrap();
        p.update_pricing_model(b, seconds, ARBOS_V30).unwrap();
        assert_eq!(p.base_fee_wei(b).unwrap(), min_price);
    }

    let mut last = p.base_fee_wei(b).unwrap();
    let mut escalated = false;
    for _ in 0..200 {
        let prev = p.gas_backlog(b).unwrap();
        p.set_gas_backlog(b, prev.saturating_add(8 * limit))
            .unwrap();
        p.update_pricing_model(b, 1, ARBOS_V30).unwrap();
        let new_price = p.base_fee_wei(b).unwrap();
        assert!(new_price >= last);
        if new_price > last {
            escalated = true;
            break;
        }
        last = new_price;
    }
    assert!(escalated);

    let baseline = p.base_fee_wei(b).unwrap();
    p.set_gas_backlog(b, limit.saturating_mul(1000)).unwrap();
    p.update_pricing_model(b, 0, ARBOS_V30).unwrap();
    p.update_pricing_model(b, 1, ARBOS_V30).unwrap();
    assert!(p.base_fee_wei(b).unwrap() > baseline);
}

#[test]
fn gas_constraints_add_open_clear() {
    let mut h = ArbosHarness::new()
        .with_arbos_version(ARBOS_V60)
        .initialize();
    let state_ptr = h.state_ptr();
    let p = h.l2_pricing_state();
    let b = unsafe { &mut *state_ptr };

    assert_eq!(p.gas_constraints_length(b).unwrap(), 0);

    const N: u64 = 10;
    for i in 0..N {
        p.add_gas_constraint(b, 100 * i + 1, 100 * i + 2, 100 * i + 3)
            .unwrap();
    }
    assert_eq!(p.gas_constraints_length(b).unwrap(), N);

    for i in 0..N {
        let c = p.open_gas_constraint_at(i);
        assert_eq!(c.target(b).unwrap(), 100 * i + 1);
        assert_eq!(c.adjustment_window(b).unwrap(), 100 * i + 2);
        assert_eq!(c.backlog(b).unwrap(), 100 * i + 3);
    }

    p.clear_gas_constraints(b).unwrap();
    assert_eq!(p.gas_constraints_length(b).unwrap(), 0);
}

#[test]
fn multi_gas_constraints_add_open_clear() {
    let mut h = ArbosHarness::new()
        .with_arbos_version(ARBOS_V60)
        .initialize();
    let state_ptr = h.state_ptr();
    let p = h.l2_pricing_state();
    let b = unsafe { &mut *state_ptr };

    assert_eq!(p.multi_gas_constraints_length(b).unwrap(), 0);

    const N: u64 = 5;
    for i in 0..N {
        let w = weights(&[
            (ResourceKind::Computation, 10 + i),
            (ResourceKind::StorageAccessRead, 20 + i),
        ]);
        p.add_multi_gas_constraint(b, 100 * i + 1, (100 * i + 2) as u32, 100 * i + 3, &w)
            .unwrap();
    }

    assert_eq!(p.multi_gas_constraints_length(b).unwrap(), N);

    for i in 0..N {
        let c = p.open_multi_gas_constraint_at(i);
        assert_eq!(c.target(b).unwrap(), 100 * i + 1);
        assert_eq!(c.adjustment_window(b).unwrap(), (100 * i + 2) as u32);
        assert_eq!(c.backlog(b).unwrap(), 100 * i + 3);
        assert_eq!(
            c.resource_weight(b, ResourceKind::Computation).unwrap(),
            10 + i
        );
        assert_eq!(
            c.resource_weight(b, ResourceKind::StorageAccessRead)
                .unwrap(),
            20 + i
        );
    }

    p.clear_multi_gas_constraints(b).unwrap();
    assert_eq!(p.multi_gas_constraints_length(b).unwrap(), 0);
}

#[test]
fn multi_gas_constraints_exponents() {
    let mut h = ArbosHarness::new()
        .with_arbos_version(ARBOS_V60)
        .initialize();
    let state_ptr = h.state_ptr();
    let p = h.l2_pricing_state();
    let b = unsafe { &mut *state_ptr };

    p.add_multi_gas_constraint(b, 100, 10, 100, &weights(&[(ResourceKind::Computation, 1)]))
        .unwrap();
    p.add_multi_gas_constraint(
        b,
        40,
        20,
        200,
        &weights(&[(ResourceKind::StorageAccessRead, 2)]),
    )
    .unwrap();

    let exps = p.calc_multi_gas_constraints_exponents(b).unwrap();
    assert_eq!(exps[ResourceKind::Computation as usize], 1000);
    assert_eq!(exps[ResourceKind::StorageAccessRead as usize], 2500);
}

#[test]
fn initial_base_fee_equals_min() {
    let mut h = ArbosHarness::new().initialize();
    let state_ptr = h.state_ptr();
    let p = h.l2_pricing_state();
    let b = unsafe { &mut *state_ptr };
    let base = p.base_fee_wei(b).unwrap();
    let min = p.min_base_fee_wei(b).unwrap();
    assert_eq!(base, min);
    assert!(base > U256::ZERO);
}

#[test]
fn multigas_refund_requires_active_constraints_starting_at_v61() {
    let mut h60 = ArbosHarness::new()
        .with_arbos_version(ARBOS_V60)
        .initialize();
    let state60 = h60.state_ptr();
    let pricing60 = h60.l2_pricing_state();
    assert!(
        pricing60
            .should_compute_multi_gas_refund(unsafe { &mut *state60 })
            .unwrap(),
        "v60 historical behavior evaluates the refund without constraints"
    );

    let mut h61 = ArbosHarness::new()
        .with_arbos_version(ARBOS_V61)
        .initialize();
    let state61 = h61.state_ptr();
    let pricing61 = h61.l2_pricing_state();
    let backend61 = unsafe { &mut *state61 };
    assert!(
        !pricing61
            .should_compute_multi_gas_refund(backend61)
            .unwrap(),
        "v61 must skip the refund until multi-gas constraints are configured"
    );

    pricing61
        .add_multi_gas_constraint(
            backend61,
            100,
            10,
            0,
            &weights(&[(ResourceKind::Computation, 1)]),
        )
        .unwrap();
    assert!(
        pricing61
            .should_compute_multi_gas_refund(backend61)
            .unwrap(),
        "v61 evaluates the refund when multi-gas constraints are active"
    );
}

#[test]
fn multigas_refund_uses_block_base_fee_starting_at_v61() {
    let stored_base_fee = U256::from(111u64);
    let block_base_fee = U256::from(222u64);

    for (version, expected) in [(ARBOS_V60, stored_base_fee), (ARBOS_V61, block_base_fee)] {
        let mut h = ArbosHarness::new().with_arbos_version(version).initialize();
        let state = h.state_ptr();
        let pricing = h.l2_pricing_state();
        let backend = unsafe { &mut *state };
        pricing.set_base_fee_wei(backend, stored_base_fee).unwrap();

        let fees = pricing
            .get_multi_gas_base_fee_per_resource(backend, block_base_fee)
            .unwrap();
        assert_eq!(fees[ResourceKind::SingleDim as usize], expected);
        assert_eq!(fees[ResourceKind::Computation as usize], expected);
    }
}

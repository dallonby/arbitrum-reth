use crate::ArbPrecompileResult as PrecompileResult;
use alloy_evm::precompiles::{DynPrecompile, PrecompileInput};
use alloy_primitives::Address;
use revm::precompile::PrecompileId;

/// ArbBLS precompile address (0x67).
pub const ARBBLS_ADDRESS: Address = Address::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x67,
]);

pub fn create_arbbls_precompile() -> DynPrecompile {
    DynPrecompile::new_stateful(PrecompileId::custom("arbbls"), |input| {
        let gas_limit = input.gas;
        let reservoir = input.reservoir;
        crate::finish_arb_precompile(handler(input), gas_limit, reservoir)
    })
}

fn handler(input: PrecompileInput<'_>) -> PrecompileResult {
    // ArbBLS is a deprecated precompile with no methods.
    crate::burn_all_revert(input.gas)
}

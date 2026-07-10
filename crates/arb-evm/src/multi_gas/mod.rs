//! Per-opcode multi-gas attribution for the v60 multi-dimensional pricing
//! model. Mirrors Nitro's per-opcode dimension assignment so the per-dimension
//! L2 pricing backlogs (and hence the base fee) match.

pub mod classify;
pub mod inspector;
pub mod intrinsic;

pub use classify::{classify, OpKind};
pub use inspector::{MultiGasInspector, MultiGasSink};
pub use intrinsic::{intrinsic_multigas, IntrinsicInput};

/// Whether to use the experimental sparse multi-gas instruction path.
///
/// Canonical node production and persistence-free sequencer execution share
/// this selector so their defaults cannot silently diverge. The generic
/// inspector remains the default until sparse execution has completed
/// differential validation.
pub fn sparse_inspector_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("ARB_SPARSE_MULTIGAS_INSPECTOR")
            .is_ok_and(|value| sparse_inspector_value(&value))
    })
}

fn sparse_inspector_value(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

#[cfg(test)]
mod tests {
    use super::sparse_inspector_value;

    #[test]
    fn sparse_inspector_is_explicitly_opt_in() {
        assert!(sparse_inspector_value("1"));
        assert!(sparse_inspector_value("TRUE"));
        assert!(!sparse_inspector_value("0"));
        assert!(!sparse_inspector_value("yes"));
        assert!(!sparse_inspector_value(""));
    }
}

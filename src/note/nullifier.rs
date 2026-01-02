use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use blake2::{Blake2s256, Digest};

/// Nullifier prevents double-spending of notes
/// nf = PRF_nf(nullifier_key, note_position)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, JsonSchema)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Derive nullifier from nullifier key and note position (rho)
    /// This prevents the same note from being spent twice
    pub fn derive(nk: &[u8; 32], rho: u64) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_nf");
        hasher.update(nk);
        hasher.update(&rho.to_le_bytes());

        let result = hasher.finalize();
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&result);
        Nullifier(nullifier)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_derivation() {
        let nk = [1u8; 32];
        let rho = 42;

        let nf1 = Nullifier::derive(&nk, rho);
        let nf2 = Nullifier::derive(&nk, rho);

        // Same inputs should produce same nullifier
        assert_eq!(nf1, nf2);

        // Different position should produce different nullifier
        let nf3 = Nullifier::derive(&nk, 43);
        assert_ne!(nf1, nf3);

        // Different key should produce different nullifier
        let nk2 = [2u8; 32];
        let nf4 = Nullifier::derive(&nk2, rho);
        assert_ne!(nf1, nf4);
    }
}

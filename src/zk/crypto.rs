use blake2::{Blake2s256, Digest};

/// Pedersen commitment: C = value*G + blinding*H
///
/// NOTE: This is a placeholder implementation for development.
/// In production, this will use curve25519-dalek or ark-curve25519
/// to compute actual Pedersen commitments on an elliptic curve.
///
/// For now, we use a hash-based commitment for structure/testing.
#[derive(Clone, Debug, PartialEq)]
pub struct PedersenCommitment(pub [u8; 32]);

impl PedersenCommitment {
    /// Create a commitment to a value with blinding factor
    ///
    /// TODO: Replace with actual elliptic curve Pedersen commitment
    /// once bulletproofs dependencies are resolved
    pub fn new(value: u64, blinding: &[u8; 32]) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_pedersen");
        hasher.update(&value.to_le_bytes());
        hasher.update(blinding);

        let result = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);

        PedersenCommitment(commitment)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PedersenCommitment(bytes)
    }
}

/// Pedersen commitment with explicit API for Bulletproofs
///
/// This matches the interface expected by bulletproofs library
pub fn pedersen_commit(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
    PedersenCommitment::new(value, blinding).to_bytes()
}

/// BLAKE2s-256 hash function
///
/// Used throughout the protocol for:
/// - Note commitments
/// - Nullifier derivation
/// - Key derivation
/// - Merkle tree hashing
pub fn blake2s_hash(domain: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(domain);
    for chunk in data {
        hasher.update(chunk);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Generate random blinding factor for Pedersen commitments
///
/// In a contract context, this would use env.block.random
/// For client-side proof generation, use a CSPRNG
pub fn random_blinding() -> [u8; 32] {
    // TODO: In contract, use env.block.random
    // For now, this is a placeholder
    [0u8; 32]
}

/// Verify Pedersen commitment opens to a specific value
///
/// Used in proofs to check that a commitment was created correctly
pub fn verify_commitment(
    commitment: &[u8; 32],
    value: u64,
    blinding: &[u8; 32],
) -> bool {
    let expected = pedersen_commit(value, blinding);
    commitment == &expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment() {
        let value = 100u64;
        let blinding = [42u8; 32];

        let commitment = PedersenCommitment::new(value, &blinding);

        // Same inputs should produce same commitment
        let commitment2 = PedersenCommitment::new(value, &blinding);
        assert_eq!(commitment, commitment2);

        // Different value should produce different commitment
        let commitment3 = PedersenCommitment::new(200, &blinding);
        assert_ne!(commitment, commitment3);

        // Different blinding should produce different commitment
        let blinding2 = [99u8; 32];
        let commitment4 = PedersenCommitment::new(value, &blinding2);
        assert_ne!(commitment, commitment4);
    }

    #[test]
    fn test_pedersen_commit_api() {
        let value = 100u64;
        let blinding = [42u8; 32];

        let commitment = pedersen_commit(value, &blinding);
        assert_eq!(commitment.len(), 32);

        // Deterministic
        let commitment2 = pedersen_commit(value, &blinding);
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_blake2s_hash() {
        let domain = b"test_domain";
        let data1 = b"hello";
        let data2 = b"world";

        let hash = blake2s_hash(domain, &[data1, data2]);
        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = blake2s_hash(domain, &[data1, data2]);
        assert_eq!(hash, hash2);

        // Different domain should produce different hash
        let hash3 = blake2s_hash(b"other_domain", &[data1, data2]);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_verify_commitment() {
        let value = 100u64;
        let blinding = [42u8; 32];

        let commitment = pedersen_commit(value, &blinding);

        // Correct value and blinding should verify
        assert!(verify_commitment(&commitment, value, &blinding));

        // Wrong value should fail
        assert!(!verify_commitment(&commitment, 200, &blinding));

        // Wrong blinding should fail
        let wrong_blinding = [99u8; 32];
        assert!(!verify_commitment(&commitment, value, &wrong_blinding));
    }
}

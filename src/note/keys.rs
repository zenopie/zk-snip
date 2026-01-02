use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use blake2::{Blake2s256, Digest};

/// Spending key - master secret (keep this private!)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SpendingKey(pub [u8; 32]);

/// Full viewing key - can view incoming and outgoing transactions
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct FullViewingKey {
    /// Authentication key
    pub ak: [u8; 32],
    /// Nullifier key
    pub nk: [u8; 32],
    /// Outgoing viewing key
    pub ovk: [u8; 32],
}

/// Incoming viewing key - can view incoming transactions only
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct IncomingViewingKey {
    pub ivk: [u8; 32],
}

/// Payment address - public address to receive payments
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PaymentAddress {
    pub diversifier: [u8; 11],
    pub pkd: [u8; 32],
}

impl SpendingKey {
    /// Generate from random bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SpendingKey(bytes)
    }

    /// Derive full viewing key from spending key
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_ak");
        hasher.update(&self.0);
        let ak_result = hasher.finalize();
        let mut ak = [0u8; 32];
        ak.copy_from_slice(&ak_result);

        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_nk");
        hasher.update(&self.0);
        let nk_result = hasher.finalize();
        let mut nk = [0u8; 32];
        nk.copy_from_slice(&nk_result);

        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_ovk");
        hasher.update(&self.0);
        let ovk_result = hasher.finalize();
        let mut ovk = [0u8; 32];
        ovk.copy_from_slice(&ovk_result);

        FullViewingKey { ak, nk, ovk }
    }
}

impl FullViewingKey {
    /// Derive incoming viewing key
    pub fn to_incoming_viewing_key(&self) -> IncomingViewingKey {
        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_ivk");
        hasher.update(&self.ak);
        hasher.update(&self.nk);
        let result = hasher.finalize();
        let mut ivk = [0u8; 32];
        ivk.copy_from_slice(&result);

        IncomingViewingKey { ivk }
    }
}

impl IncomingViewingKey {
    /// Derive payment address from diversifier
    pub fn to_payment_address(&self, diversifier: [u8; 11]) -> PaymentAddress {
        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_pkd");
        hasher.update(&self.ivk);
        hasher.update(&diversifier);
        let result = hasher.finalize();
        let mut pkd = [0u8; 32];
        pkd.copy_from_slice(&result);

        PaymentAddress { diversifier, pkd }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let sk = SpendingKey([1u8; 32]);
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();
        let diversifier = [2u8; 11];
        let addr = ivk.to_payment_address(diversifier);

        // Same spending key should produce same keys
        let sk2 = SpendingKey([1u8; 32]);
        let fvk2 = sk2.to_full_viewing_key();
        assert_eq!(fvk.ak, fvk2.ak);
        assert_eq!(fvk.nk, fvk2.nk);

        // Different spending key should produce different keys
        let sk3 = SpendingKey([2u8; 32]);
        let fvk3 = sk3.to_full_viewing_key();
        assert_ne!(fvk.ak, fvk3.ak);

        // Same diversifier should produce same address
        let addr2 = ivk.to_payment_address(diversifier);
        assert_eq!(addr.pkd, addr2.pkd);

        // Different diversifier should produce different address
        let diversifier2 = [3u8; 11];
        let addr3 = ivk.to_payment_address(diversifier2);
        assert_ne!(addr.pkd, addr3.pkd);
    }
}

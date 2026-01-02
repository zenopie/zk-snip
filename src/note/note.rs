use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

/// A private note containing value and metadata (similar to Zcash Sapling)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Note {
    /// Diversifier - enables multiple payment addresses from one key
    pub diversifier: [u8; 11],

    /// Payment address public key (derived from diversifier + viewing key)
    pub pkd: [u8; 32],

    /// Note value in base units
    pub value: u64,

    /// Random commitment trapdoor for hiding the note
    pub rcm: [u8; 32],
}

impl Note {
    /// Create a new note
    pub fn new(
        diversifier: [u8; 11],
        pkd: [u8; 32],
        value: u64,
        rcm: [u8; 32],
    ) -> Self {
        Note {
            diversifier,
            pkd,
            value,
            rcm,
        }
    }

    /// Get the commitment to this note
    /// cm = Hash(diversifier || pkd || value || rcm)
    pub fn commitment(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};

        let mut hasher = Blake2s256::new();
        hasher.update(b"ZkSnip_note_cm");
        hasher.update(&self.diversifier);
        hasher.update(&self.pkd);
        hasher.update(&self.value.to_le_bytes());
        hasher.update(&self.rcm);

        let result = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);
        commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_commitment() {
        let note = Note {
            diversifier: [1u8; 11],
            pkd: [2u8; 32],
            value: 1000,
            rcm: [3u8; 32],
        };

        let cm1 = note.commitment();
        let cm2 = note.commitment();

        // Same note should produce same commitment
        assert_eq!(cm1, cm2);

        // Different value should produce different commitment
        let note2 = Note {
            value: 2000,
            ..note.clone()
        };
        assert_ne!(note.commitment(), note2.commitment());
    }
}

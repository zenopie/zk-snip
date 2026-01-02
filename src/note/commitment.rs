use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

/// Note commitment - cryptographic commitment to a note
/// Hides the note contents while allowing verification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, JsonSchema)]
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NoteCommitment(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(NoteCommitment(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_hex() {
        let commitment = NoteCommitment([1u8; 32]);
        let hex = commitment.to_hex();
        let parsed = NoteCommitment::from_hex(&hex).unwrap();
        assert_eq!(commitment, parsed);
    }
}

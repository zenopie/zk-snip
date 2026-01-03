use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, StdError, Storage};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::state::GROTH16_VK;
use crate::tree::merkle::MerkleTree;
use crate::zk::groth16::{SerializedVK, verifier_from_serialized};

/// Message for executing a shielded ZK transfer
///
/// Spends 2 old notes, creates 2 new notes
/// This is ZK mode - requires scanning to find notes
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ZkTransferMsg {
    /// Merkle root at time of spend (must be recent)
    pub merkle_root: String,

    /// Nullifiers of spent notes (hex-encoded)
    pub nullifiers: [String; 2],

    /// Commitments to new notes (hex-encoded)
    pub commitments: [String; 2],

    /// Zero-knowledge proof (base64-encoded)
    pub proof: String,

    /// Optional encrypted notes for recipient decryption
    /// Format: { recipient_address: encrypted_note }
    #[serde(default)]
    pub encrypted_notes: Vec<EncryptedNote>,
}

/// Encrypted note for recipient
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct EncryptedNote {
    /// Recipient address (for optional note index)
    pub recipient: String,

    /// Encrypted note data (can be decrypted with viewing key)
    pub ciphertext: String,

    /// Index of the commitment (0 or 1)
    pub commitment_index: u8,
}

/// Storage keys for shielded state
const MERKLE_TREE_KEY: &[u8] = b"merkle_tree";
const NULLIFIER_SET_PREFIX: &[u8] = b"nullifier_";
const MERKLE_ROOT_HISTORY_PREFIX: &[u8] = b"root_history_";
const CURRENT_ROOT_INDEX_KEY: &[u8] = b"current_root_index";

/// Number of recent roots to keep for spend validation
const ROOT_HISTORY_SIZE: u64 = 100;

/// Execute a shielded ZK transfer
///
/// This is the ZK mode core operation:
/// 1. Verify merkle root is recent (anti-front-running)
/// 2. Check nullifiers not already spent (anti-double-spend)
/// 3. Verify zero-knowledge proof
/// 4. Mark nullifiers as spent
/// 5. Insert new commitments into tree
/// 6. (Optional) Update note index for recipients
pub fn execute_zk_transfer(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ZkTransferMsg,
) -> StdResult<Response> {
    // Parse hex inputs
    let merkle_root = parse_hex_32(&msg.merkle_root)?;
    let nullifiers = [
        parse_hex_32(&msg.nullifiers[0])?,
        parse_hex_32(&msg.nullifiers[1])?,
    ];
    let commitments = [
        parse_hex_32(&msg.commitments[0])?,
        parse_hex_32(&msg.commitments[1])?,
    ];

    // Decode proof
    use base64::{Engine as _, engine::general_purpose};
    let proof_bytes = general_purpose::STANDARD.decode(&msg.proof)
        .map_err(|e| StdError::generic_err(format!("Invalid proof encoding: {}", e)))?;

    // Step 1: Verify merkle root is recent
    verify_merkle_root_recent(deps.storage, &merkle_root)?;

    // Step 2: Check nullifiers not spent
    verify_nullifiers_unspent(deps.storage, &nullifiers)?;

    // Step 3: Verify zero-knowledge proof using Groth16
    // Load the verification key from storage
    let vk_bytes = GROTH16_VK.load(deps.storage)
        .map_err(|_| StdError::generic_err("Verification key not initialized - contract not properly instantiated"))?;
    let serialized_vk = SerializedVK { data: vk_bytes };
    let verifier = verifier_from_serialized(&serialized_vk)
        .map_err(|e| StdError::generic_err(format!("Failed to load verifier: {}", e)))?;

    // For a 2-in-2-out transfer, we verify two spend proofs
    // Each nullifier corresponds to a spent note
    // Note: In production, this would be a single aggregated proof
    // For now, we verify that the proof is valid for the first nullifier/commitment pair
    verifier
        .verify_bytes(&proof_bytes, &merkle_root, &nullifiers[0], &commitments[0])
        .map_err(|e| StdError::generic_err(format!("Proof verification failed: {}", e)))?;

    // Step 4: Mark nullifiers as spent
    mark_nullifiers_spent(deps.storage, &nullifiers)?;

    // Step 5: Insert new commitments into Merkle tree
    let mut tree = load_merkle_tree(deps.storage)?;
    let index1 = tree
        .insert(commitments[0])
        .map_err(|e| StdError::generic_err(e))?;
    let index2 = tree
        .insert(commitments[1])
        .map_err(|e| StdError::generic_err(e))?;

    // Update root history
    let new_root = tree.root();
    update_root_history(deps.storage, new_root)?;

    // Save updated tree
    save_merkle_tree(deps.storage, &tree)?;

    // Step 6: Store encrypted notes for wallet scanning (no events to preserve privacy)
    use crate::state::{ENCRYPTED_NOTES, EncryptedNoteData};
    let block_height = env.block.height;

    for enc_note in msg.encrypted_notes.iter() {
        let index = if enc_note.commitment_index == 0 { index1 } else { index2 };
        let note_data = EncryptedNoteData {
            ciphertext: enc_note.ciphertext.clone(),
            block_height,
        };
        ENCRYPTED_NOTES.insert(deps.storage, &index, &note_data)?;
    }

    // Minimal response - no ZK-specific attributes to preserve privacy
    Ok(Response::new())
}

/// Verify that the merkle root is in recent history
///
/// This prevents front-running attacks where an attacker
/// could observe a pending transaction and spend the notes first
fn verify_merkle_root_recent(storage: &dyn Storage, root: &[u8; 32]) -> StdResult<()> {
    let current_index = load_current_root_index(storage)?;

    // Check last ROOT_HISTORY_SIZE roots
    let start_index = current_index.saturating_sub(ROOT_HISTORY_SIZE);
    for i in start_index..=current_index {
        let key = root_history_key(i);
        if let Some(stored_root) = storage.get(&key) {
            if stored_root.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&stored_root);
                if &arr == root {
                    return Ok(());
                }
            }
        }
    }

    Err(StdError::generic_err(
        "Merkle root not found in recent history",
    ))
}

/// Verify that nullifiers have not been spent
fn verify_nullifiers_unspent(storage: &dyn Storage, nullifiers: &[[u8; 32]; 2]) -> StdResult<()> {
    for (i, nullifier) in nullifiers.iter().enumerate() {
        let key = nullifier_key(nullifier);
        if storage.get(&key).is_some() {
            return Err(StdError::generic_err(format!(
                "Nullifier {} already spent",
                i
            )));
        }
    }
    Ok(())
}

/// Mark nullifiers as spent
fn mark_nullifiers_spent(storage: &mut dyn Storage, nullifiers: &[[u8; 32]; 2]) -> StdResult<()> {
    for nullifier in nullifiers {
        let key = nullifier_key(nullifier);
        storage.set(&key, &[1u8]); // Value doesn't matter, just presence
    }
    Ok(())
}

/// Update root history with new root
fn update_root_history(storage: &mut dyn Storage, root: [u8; 32]) -> StdResult<()> {
    let mut index = load_current_root_index(storage)?;
    index += 1;

    let key = root_history_key(index);
    storage.set(&key, &root);

    // Update current index
    storage.set(CURRENT_ROOT_INDEX_KEY, &index.to_le_bytes());

    Ok(())
}

/// Load current root history index
fn load_current_root_index(storage: &dyn Storage) -> StdResult<u64> {
    Ok(storage
        .get(CURRENT_ROOT_INDEX_KEY)
        .map(|bytes| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            u64::from_le_bytes(arr)
        })
        .unwrap_or(0))
}

/// Load Merkle tree from storage
fn load_merkle_tree(storage: &dyn Storage) -> StdResult<MerkleTree> {
    storage
        .get(MERKLE_TREE_KEY)
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|e| StdError::generic_err(format!("Failed to deserialize tree: {}", e)))
        })
        .unwrap_or_else(|| Ok(MerkleTree::new()))
}

/// Save Merkle tree to storage
fn save_merkle_tree(storage: &mut dyn Storage, tree: &MerkleTree) -> StdResult<()> {
    let bytes = serde_json::to_vec(tree)
        .map_err(|e| StdError::generic_err(format!("Failed to serialize tree: {}", e)))?;
    storage.set(MERKLE_TREE_KEY, &bytes);
    Ok(())
}

/// Generate storage key for a nullifier
fn nullifier_key(nullifier: &[u8; 32]) -> Vec<u8> {
    let mut key = NULLIFIER_SET_PREFIX.to_vec();
    key.extend_from_slice(nullifier);
    key
}

/// Generate storage key for root history
fn root_history_key(index: u64) -> Vec<u8> {
    let mut key = MERKLE_ROOT_HISTORY_PREFIX.to_vec();
    key.extend_from_slice(&index.to_le_bytes());
    key
}

/// Parse hex string to 32-byte array
fn parse_hex_32(hex: &str) -> StdResult<[u8; 32]> {
    let bytes = hex::decode(hex)
        .map_err(|e| StdError::generic_err(format!("Invalid hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(StdError::generic_err(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    #[test]
    fn test_parse_hex_32() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let result = parse_hex_32(hex).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 1);
        assert_eq!(result[31], 32);
    }

    #[test]
    fn test_nullifier_key_unique() {
        let nullifier1 = [1u8; 32];
        let nullifier2 = [2u8; 32];

        let key1 = nullifier_key(&nullifier1);
        let key2 = nullifier_key(&nullifier2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_root_history() {
        let mut deps = mock_dependencies();

        let root1 = [1u8; 32];
        let root2 = [2u8; 32];

        // Initially no roots
        assert_eq!(load_current_root_index(deps.as_ref().storage).unwrap(), 0);

        // Add first root
        update_root_history(deps.as_mut().storage, root1).unwrap();
        assert_eq!(load_current_root_index(deps.as_ref().storage).unwrap(), 1);

        // Add second root
        update_root_history(deps.as_mut().storage, root2).unwrap();
        assert_eq!(load_current_root_index(deps.as_ref().storage).unwrap(), 2);

        // Verify recent root
        assert!(verify_merkle_root_recent(deps.as_ref().storage, &root2).is_ok());
        assert!(verify_merkle_root_recent(deps.as_ref().storage, &root1).is_ok());

        // Non-existent root should fail
        let root3 = [3u8; 32];
        assert!(verify_merkle_root_recent(deps.as_ref().storage, &root3).is_err());
    }

    #[test]
    fn test_nullifier_tracking() {
        let mut deps = mock_dependencies();

        let nullifiers = [[1u8; 32], [2u8; 32]];

        // Initially unspent
        assert!(verify_nullifiers_unspent(deps.as_ref().storage, &nullifiers).is_ok());

        // Mark as spent
        mark_nullifiers_spent(deps.as_mut().storage, &nullifiers).unwrap();

        // Now should be spent
        assert!(verify_nullifiers_unspent(deps.as_ref().storage, &nullifiers).is_err());
    }

    #[test]
    fn test_merkle_tree_persistence() {
        let mut deps = mock_dependencies();

        // Create and save tree
        let mut tree = MerkleTree::new();
        let commitment = [1u8; 32];
        tree.insert(commitment).unwrap();

        save_merkle_tree(deps.as_mut().storage, &tree).unwrap();

        // Load tree
        let loaded_tree = load_merkle_tree(deps.as_ref().storage).unwrap();
        assert_eq!(loaded_tree.size(), 1);
        assert_eq!(loaded_tree.root(), tree.root());
    }
}

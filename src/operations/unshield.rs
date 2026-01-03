use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, StdError, Uint128, Storage};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::state::{BALANCES, ENCRYPTED_NOTES, EncryptedNoteData, GROTH16_VK};
use crate::tree::merkle::MerkleTree;
use crate::zk::groth16::{SerializedVK, verifier_from_serialized};

/// Message for unshielding ZK note into TEE balance
///
/// Converts: ZK mode (note) → TEE mode (account balance)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UnshieldMsg {
    /// Recipient address (where TEE balance will be added)
    pub recipient: String,

    /// Amount being unshielded
    pub amount: Uint128,

    /// Merkle root at time of spend (must be recent)
    pub merkle_root: String,

    /// Nullifier of the note being spent (hex-encoded)
    pub nullifier: String,

    /// Commitment to change note (hex-encoded)
    /// If spending note worth 100 to unshield 60, commitment is for 40 change
    pub change_commitment: String,

    /// Zero-knowledge proof (base64-encoded)
    /// Proves: ownership of note, correct nullifier, correct change
    pub proof: String,

    /// Optional encrypted change note for sender's wallet scanning
    #[serde(default)]
    pub encrypted_change_note: Option<String>,
}

const MERKLE_TREE_KEY: &[u8] = b"merkle_tree";
const NULLIFIER_SET_PREFIX: &[u8] = b"nullifier_";
const MERKLE_ROOT_HISTORY_PREFIX: &[u8] = b"root_history_";
const CURRENT_ROOT_INDEX_KEY: &[u8] = b"current_root_index";
const ROOT_HISTORY_SIZE: u64 = 100;

/// Execute unshield operation: ZK note → TEE balance
///
/// Flow:
/// 1. Verify merkle root is recent
/// 2. Check nullifier not already spent
/// 3. Verify zero-knowledge proof
/// 4. Mark nullifier as spent
/// 5. Add amount to recipient's TEE balance
/// 6. Insert change commitment into tree
pub fn execute_unshield(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: UnshieldMsg,
) -> StdResult<Response> {
    // Parse inputs
    let merkle_root = parse_hex_32(&msg.merkle_root)?;
    let nullifier = parse_hex_32(&msg.nullifier)?;
    let change_commitment = parse_hex_32(&msg.change_commitment)?;

    // Decode proof
    use base64::{Engine as _, engine::general_purpose};
    let proof_bytes = general_purpose::STANDARD.decode(&msg.proof)
        .map_err(|e| StdError::generic_err(format!("Invalid proof encoding: {}", e)))?;

    // Step 1: Verify merkle root is recent
    verify_merkle_root_recent(deps.storage, &merkle_root)?;

    // Step 2: Check nullifier not spent
    verify_nullifier_unspent(deps.storage, &nullifier)?;

    // Step 3: Verify zero-knowledge proof using Groth16
    // Public inputs: merkle_root, nullifier, change_commitment
    // Proof shows: I own a note, here's its nullifier, here's change commitment
    let vk_bytes = GROTH16_VK.load(deps.storage)
        .map_err(|_| StdError::generic_err("Verification key not initialized - contract not properly instantiated"))?;
    let serialized_vk = SerializedVK { data: vk_bytes };
    let verifier = verifier_from_serialized(&serialized_vk)
        .map_err(|e| StdError::generic_err(format!("Failed to load verifier: {}", e)))?;

    verifier
        .verify_bytes(&proof_bytes, &merkle_root, &nullifier, &change_commitment)
        .map_err(|e| StdError::generic_err(format!("Proof verification failed: {}", e)))?;

    // Step 4: Mark nullifier as spent
    mark_nullifier_spent(deps.storage, &nullifier)?;

    // Step 5: Add to recipient's TEE balance
    let recipient_raw = deps.api.addr_canonicalize(&msg.recipient)?;
    let mut balance = BALANCES
        .get(deps.storage, &recipient_raw)
        .unwrap_or_default();

    balance = balance.checked_add(msg.amount)?;
    BALANCES.insert(deps.storage, &recipient_raw, &balance)?;

    // Step 6: Insert change commitment into tree (if non-zero)
    let zero_commitment = [0u8; 32];
    if change_commitment != zero_commitment {
        let mut tree = load_merkle_tree(deps.storage)?;
        let index = tree
            .insert(change_commitment)
            .map_err(|e| StdError::generic_err(e))?;

        // Update root history
        let new_root = tree.root();
        update_root_history(deps.storage, new_root)?;

        // Save updated tree
        save_merkle_tree(deps.storage, &tree)?;

        // Store encrypted change note if provided
        if let Some(ref enc_note) = msg.encrypted_change_note {
            let note_data = EncryptedNoteData {
                ciphertext: enc_note.clone(),
                block_height: env.block.height,
            };
            ENCRYPTED_NOTES.insert(deps.storage, &index, &note_data)?;
        }
    }

    // Minimal response - no ZK-specific attributes to preserve privacy
    Ok(Response::new())
}

/// Verify that the merkle root is in recent history
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

/// Verify that nullifier has not been spent
fn verify_nullifier_unspent(storage: &dyn Storage, nullifier: &[u8; 32]) -> StdResult<()> {
    let key = nullifier_key(nullifier);
    if storage.get(&key).is_some() {
        return Err(StdError::generic_err("Nullifier already spent"));
    }
    Ok(())
}

/// Mark nullifier as spent
fn mark_nullifier_spent(storage: &mut dyn Storage, nullifier: &[u8; 32]) -> StdResult<()> {
    let key = nullifier_key(nullifier);
    storage.set(&key, &[1u8]); // Value doesn't matter, just presence
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

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::Addr;

    #[test]
    fn test_unshield_nullifier_tracking() {
        let mut deps = mock_dependencies();

        let nullifier = [42u8; 32];

        // Initially unspent
        assert!(verify_nullifier_unspent(deps.as_ref().storage, &nullifier).is_ok());

        // Mark as spent
        mark_nullifier_spent(deps.as_mut().storage, &nullifier).unwrap();

        // Now should be spent
        assert!(verify_nullifier_unspent(deps.as_ref().storage, &nullifier).is_err());
    }

    #[test]
    fn test_parse_hex_32() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let result = parse_hex_32(hex).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 1);
        assert_eq!(result[31], 32);
    }
}

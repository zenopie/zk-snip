use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, StdError, Uint128};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::tree::merkle::MerkleTree;
use crate::state::BALANCES;

/// Message for shielding TEE balance into ZK note
///
/// Converts: TEE mode (account balance) → ZK mode (note commitment)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ShieldMsg {
    /// Amount to shield from TEE balance
    pub amount: Uint128,

    /// Note commitment to create (hex-encoded)
    /// Client generates this from: Hash(diversifier || pkd || amount || rcm)
    pub commitment: String,

    /// Optional encrypted note data for client wallet
    pub encrypted_note: Option<String>,
}

const MERKLE_TREE_KEY: &[u8] = b"merkle_tree";
const MERKLE_ROOT_HISTORY_PREFIX: &[u8] = b"root_history_";
const CURRENT_ROOT_INDEX_KEY: &[u8] = b"current_root_index";

/// Execute shield operation: TEE balance → ZK note
///
/// Flow:
/// 1. Verify user has sufficient TEE balance
/// 2. Deduct amount from TEE balance
/// 3. Insert commitment into Merkle tree
/// 4. User can now spend the note privately using ZK proofs
pub fn execute_shield(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ShieldMsg,
) -> StdResult<Response> {
    let sender_raw = deps.api.addr_canonicalize(info.sender.as_str())?;

    // Parse commitment
    let commitment = parse_hex_32(&msg.commitment)?;

    // Step 1: Check TEE balance
    let mut balance = BALANCES
        .get(deps.storage, &sender_raw)
        .unwrap_or_default();

    if balance < msg.amount {
        return Err(StdError::generic_err(format!(
            "Insufficient TEE balance: have {}, need {}",
            balance, msg.amount
        )));
    }

    // Step 2: Deduct from TEE balance
    balance = balance.checked_sub(msg.amount)?;
    BALANCES.insert(deps.storage, &sender_raw, &balance)?;

    // Step 3: Insert commitment into Merkle tree
    let mut tree = load_merkle_tree(deps.storage)?;
    let index = tree
        .insert(commitment)
        .map_err(|e| StdError::generic_err(e))?;

    // Update root history
    let new_root = tree.root();
    update_root_history(deps.storage, new_root)?;

    // Save updated tree
    save_merkle_tree(deps.storage, &tree)?;

    // Store encrypted note for wallet scanning (if provided)
    if let Some(ref enc_note) = msg.encrypted_note {
        use crate::state::{ENCRYPTED_NOTES, EncryptedNoteData};
        let note_data = EncryptedNoteData {
            ciphertext: enc_note.clone(),
            block_height: env.block.height,
        };
        ENCRYPTED_NOTES.insert(deps.storage, &index, &note_data)?;
    }

    // Minimal response - no ZK-specific attributes to preserve privacy
    Ok(Response::new())
}

/// Load Merkle tree from storage
fn load_merkle_tree(storage: &dyn cosmwasm_std::Storage) -> StdResult<MerkleTree> {
    storage
        .get(MERKLE_TREE_KEY)
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|e| StdError::generic_err(format!("Failed to deserialize tree: {}", e)))
        })
        .unwrap_or_else(|| Ok(MerkleTree::new()))
}

/// Save Merkle tree to storage
fn save_merkle_tree(storage: &mut dyn cosmwasm_std::Storage, tree: &MerkleTree) -> StdResult<()> {
    let bytes = serde_json::to_vec(tree)
        .map_err(|e| StdError::generic_err(format!("Failed to serialize tree: {}", e)))?;
    storage.set(MERKLE_TREE_KEY, &bytes);
    Ok(())
}

/// Update root history with new root
fn update_root_history(storage: &mut dyn cosmwasm_std::Storage, root: [u8; 32]) -> StdResult<()> {
    let mut index = load_current_root_index(storage)?;
    index += 1;

    let key = root_history_key(index);
    storage.set(&key, &root);

    // Update current index
    storage.set(CURRENT_ROOT_INDEX_KEY, &index.to_le_bytes());

    Ok(())
}

/// Load current root history index
fn load_current_root_index(storage: &dyn cosmwasm_std::Storage) -> StdResult<u64> {
    Ok(storage
        .get(CURRENT_ROOT_INDEX_KEY)
        .map(|bytes| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            u64::from_le_bytes(arr)
        })
        .unwrap_or(0))
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

    #[test]
    fn test_parse_hex_32() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let result = parse_hex_32(hex).unwrap();
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 1);
        assert_eq!(result[31], 32);
    }

    // Note: Full integration tests with balance operations require
    // Secret Network specific test infrastructure.
    // These tests should be run as integration tests with proper setup.
}

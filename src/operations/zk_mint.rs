use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, StdError, Uint128, Storage};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::tree::merkle::MerkleTree;
use crate::state::{CONFIG, TOTAL_SUPPLY};

/// Message for minting new ZK notes
///
/// Creates new notes out of thin air (increases total supply)
/// Only admin can mint
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ZkMintMsg {
    /// Commitment to the new note (hex-encoded)
    pub commitment: String,

    /// Amount being minted
    pub amount: Uint128,

    /// Optional encrypted note data
    pub encrypted_note: Option<String>,
}

const MERKLE_TREE_KEY: &[u8] = b"merkle_tree";
const MERKLE_ROOT_HISTORY_PREFIX: &[u8] = b"root_history_";
const CURRENT_ROOT_INDEX_KEY: &[u8] = b"current_root_index";

/// Execute ZK mint: Create note from nothing
///
/// Flow:
/// 1. Verify sender is admin
/// 2. Increase total supply
/// 3. Insert commitment into Merkle tree
/// 4. Update root history
pub fn execute_zk_mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ZkMintMsg,
) -> StdResult<Response> {
    // Step 1: Verify admin
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.admin {
        return Err(StdError::generic_err("Unauthorized: only admin can mint"));
    }

    // Check if minting is enabled
    if !config.mint_is_enabled {
        return Err(StdError::generic_err("Minting is disabled"));
    }

    // Parse commitment
    let commitment = parse_hex_32(&msg.commitment)?;

    // Step 2: Increase total supply
    let mut total_supply = TOTAL_SUPPLY.load(deps.storage).unwrap_or_default();
    total_supply = total_supply
        .checked_add(msg.amount.u128())
        .ok_or_else(|| StdError::generic_err("Total supply overflow"))?;
    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

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

    let resp = Response::new()
        .add_attribute("action", "zk_mint")
        .add_attribute("minter", info.sender.as_str())
        .add_attribute("amount", msg.amount.to_string())
        .add_attribute("commitment_index", index.to_string())
        .add_attribute("new_root", hex::encode(new_root))
        .add_attribute("total_supply", total_supply.to_string());

    Ok(resp)
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

    // Note: Full integration tests require Secret Network test infrastructure
}

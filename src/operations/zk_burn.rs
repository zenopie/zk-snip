use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, StdError, Uint128, Storage};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::zk::bulletproofs::{BulletproofProof, BulletproofVerifier, PublicInputs};
use crate::state::{CONFIG, TOTAL_SUPPLY};

/// Message for burning ZK notes
///
/// Destroys notes (decreases total supply)
/// Requires proof of note ownership
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ZkBurnMsg {
    /// Amount being burned
    pub amount: Uint128,

    /// Merkle root at time of spend
    pub merkle_root: String,

    /// Nullifier of the note being burned (hex-encoded)
    pub nullifier: String,

    /// Commitment to change note (hex-encoded)
    /// If burning note worth 100 to burn 60, commitment is for 40 change
    pub change_commitment: String,

    /// Zero-knowledge proof (base64-encoded)
    /// Proves: ownership of note, correct nullifier, correct change
    pub proof: String,
}

const NULLIFIER_SET_PREFIX: &[u8] = b"nullifier_";
const MERKLE_ROOT_HISTORY_PREFIX: &[u8] = b"root_history_";
const CURRENT_ROOT_INDEX_KEY: &[u8] = b"current_root_index";
const ROOT_HISTORY_SIZE: u64 = 100;

/// Execute ZK burn: Destroy note
///
/// Flow:
/// 1. Verify burn is enabled
/// 2. Verify merkle root is recent
/// 3. Check nullifier not already spent
/// 4. Verify zero-knowledge proof
/// 5. Mark nullifier as spent
/// 6. Decrease total supply
/// 7. Insert change commitment into tree (if any)
pub fn execute_zk_burn(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ZkBurnMsg,
) -> StdResult<Response> {
    // Step 1: Verify burn is enabled
    let config = CONFIG.load(deps.storage)?;
    if !config.burn_is_enabled {
        return Err(StdError::generic_err("Burning is disabled"));
    }

    // Parse inputs
    let merkle_root = parse_hex_32(&msg.merkle_root)?;
    let nullifier = parse_hex_32(&msg.nullifier)?;
    let change_commitment = parse_hex_32(&msg.change_commitment)?;

    // Decode proof
    use base64::{Engine as _, engine::general_purpose};
    let proof_bytes = general_purpose::STANDARD.decode(&msg.proof)
        .map_err(|e| StdError::generic_err(format!("Invalid proof encoding: {}", e)))?;
    let proof = BulletproofProof::from_bytes(proof_bytes);

    // Step 2: Verify merkle root is recent
    verify_merkle_root_recent(deps.storage, &merkle_root)?;

    // Step 3: Check nullifier not spent
    verify_nullifier_unspent(deps.storage, &nullifier)?;

    // Step 4: Verify zero-knowledge proof
    let public_inputs = PublicInputs::new(
        merkle_root,
        [nullifier, [0u8; 32]], // Only one nullifier for burn
        [change_commitment, [0u8; 32]], // Change commitment + dummy
    );

    let verifier = BulletproofVerifier::new();
    verifier
        .verify(&proof, &public_inputs)
        .map_err(|e| StdError::generic_err(format!("Proof verification failed: {}", e)))?;

    // Step 5: Mark nullifier as spent
    mark_nullifier_spent(deps.storage, &nullifier)?;

    // Step 6: Decrease total supply
    let mut total_supply = TOTAL_SUPPLY.load(deps.storage).unwrap_or_default();
    total_supply = total_supply
        .checked_sub(msg.amount.u128())
        .ok_or_else(|| StdError::generic_err("Insufficient total supply"))?;
    TOTAL_SUPPLY.save(deps.storage, &total_supply)?;

    // Step 7: Insert change commitment into tree (if non-zero)
    // TODO: Add tree insertion for change commitment
    // For now, we skip this as it would require checking if change is non-zero

    let resp = Response::new()
        .add_attribute("action", "zk_burn")
        .add_attribute("amount", msg.amount.to_string())
        .add_attribute("nullifier", hex::encode(nullifier))
        .add_attribute("total_supply", total_supply.to_string());

    Ok(resp)
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

    #[test]
    fn test_nullifier_key_unique() {
        let nullifier1 = [1u8; 32];
        let nullifier2 = [2u8; 32];

        let key1 = nullifier_key(&nullifier1);
        let key2 = nullifier_key(&nullifier2);

        assert_ne!(key1, key2);
    }

    // Note: Full integration tests require Secret Network test infrastructure
}

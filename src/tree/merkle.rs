use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use blake2::{Blake2s256, Digest};

/// Merkle tree depth (2^32 = 4 billion max commitments)
pub const MERKLE_DEPTH: usize = 32;

/// Merkle tree for note commitments with frontier optimization
/// Only stores the rightmost path (~32 nodes) instead of the full tree
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct MerkleTree {
    /// Frontier nodes (rightmost path to next insertion point)
    frontier: Vec<Option<[u8; 32]>>,

    /// Number of commitments inserted
    size: u64,

    /// Cached merkle root
    root: [u8; 32],

    /// Recent commitments for path reconstruction (temporary solution)
    /// In production, use events or full tree storage
    #[serde(skip)]
    commitments: Vec<[u8; 32]>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        let mut tree = MerkleTree {
            frontier: vec![None; MERKLE_DEPTH],
            size: 0,
            root: [0u8; 32],
            commitments: Vec::new(),
        };
        tree.root = tree.compute_root();
        tree
    }

    /// Insert a new commitment into the tree
    pub fn insert(&mut self, commitment: [u8; 32]) -> Result<u64, String> {
        if self.size >= (1u64 << MERKLE_DEPTH) {
            return Err("Merkle tree is full".to_string());
        }

        let index = self.size;
        self.size += 1;

        // Store commitment for path reconstruction
        self.commitments.push(commitment);

        // Update frontier
        self.update_frontier(index, commitment);

        // Recompute root
        self.root = self.compute_root();

        Ok(index)
    }

    /// Update frontier nodes after inserting a commitment
    fn update_frontier(&mut self, index: u64, commitment: [u8; 32]) {
        let mut current = commitment;
        let mut idx = index;

        for (level, slot) in self.frontier.iter_mut().enumerate() {
            if idx % 2 == 0 {
                // Left child - store in frontier
                *slot = Some(current);
                break;
            } else {
                // Right child - hash with sibling and continue up
                if let Some(left) = slot.take() {
                    current = hash_pair(&left, &current);
                } else {
                    // This shouldn't happen in a properly maintained tree
                    *slot = Some(current);
                    break;
                }
            }
            idx /= 2;
        }
    }

    /// Compute the Merkle root from stored commitments
    fn compute_root(&self) -> [u8; 32] {
        if self.size == 0 {
            return empty_node_at_level(MERKLE_DEPTH - 1);
        }

        // Build the tree level by level, going all the way to the root
        let mut level = self.commitments.clone();

        // Pad with empty nodes to make a full level
        while level.len() < (1 << 0) && level.len() > 0 {
            level.push([0u8; 32]);
        }

        for depth in 0..MERKLE_DEPTH {
            if level.len() == 1 {
                // Continue hashing with empty siblings to reach full depth
                let mut current = level[0];
                for remaining_depth in depth..MERKLE_DEPTH {
                    let empty = empty_node_at_level(remaining_depth);
                    current = hash_pair(&current, &empty);
                }
                return current;
            }

            let mut next_level = Vec::new();
            for i in (0..level.len()).step_by(2) {
                let left = level[i];
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    [0u8; 32] // Empty node for odd-sized levels
                };
                next_level.push(hash_pair(&left, &right));
            }
            level = next_level;
        }

        level[0]
    }

    /// Get the current Merkle root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get the number of commitments in the tree
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Generate a Merkle path (authentication path) for a given index
    pub fn path(&self, index: u64) -> Result<Vec<[u8; 32]>, String> {
        if index >= self.size {
            return Err("Index out of bounds".to_string());
        }

        let mut path = Vec::with_capacity(MERKLE_DEPTH);
        let mut idx = index;

        for level in 0..MERKLE_DEPTH {
            let sibling_idx = idx ^ 1; // XOR with 1 flips the last bit

            // Calculate how many leaves exist at this level
            let leaves_at_level = (self.size + (1 << level) - 1) >> level;

            let sibling = if sibling_idx < leaves_at_level {
                // Sibling exists in tree
                self.get_node_at(level, sibling_idx)
            } else {
                // Sibling is empty
                empty_node_at_level(level)
            };

            path.push(sibling);
            idx >>= 1; // Move up to parent level
        }

        Ok(path)
    }

    /// Get a node at a specific level and index (reconstructed from commitments)
    fn get_node_at(&self, level: usize, index: u64) -> [u8; 32] {
        if level == 0 {
            // Leaf level - return commitment if it exists
            return self.commitments.get(index as usize).copied().unwrap_or([0u8; 32]);
        }

        // For internal nodes, reconstruct by hashing children
        let left_child = self.get_node_at(level - 1, index * 2);
        let right_child = self.get_node_at(level - 1, index * 2 + 1);
        hash_pair(&left_child, &right_child)
    }

    /// Verify a Merkle path
    pub fn verify_path(
        leaf: [u8; 32],
        index: u64,
        path: &[[u8; 32]],
        root: [u8; 32],
    ) -> bool {
        let mut current = leaf;
        let mut idx = index;

        for sibling in path {
            if idx % 2 == 0 {
                // Current is left child
                current = hash_pair(&current, sibling);
            } else {
                // Current is right child
                current = hash_pair(sibling, &current);
            }
            idx >>= 1; // Use shift instead of division for consistency
        }

        current == root
    }
}

/// Hash two nodes together (left || right)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"ZkSnip_merkle");
    hasher.update(left);
    hasher.update(right);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Get the empty node value at a given level
fn empty_node_at_level(level: usize) -> [u8; 32] {
    // In production, these would be precomputed constants
    let mut node = [0u8; 32];
    for _ in 0..level {
        node = hash_pair(&node, &node);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_empty() {
        let tree = MerkleTree::new();
        assert_eq!(tree.size(), 0);
        // Empty tree root is deterministic
        let empty_root = tree.root();
        assert_eq!(empty_root.len(), 32);
    }

    #[test]
    fn test_merkle_tree_insert() {
        let mut tree = MerkleTree::new();

        let commitment1 = [1u8; 32];
        let commitment2 = [2u8; 32];

        let idx1 = tree.insert(commitment1).unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(tree.size(), 1);

        let root1 = tree.root();

        let idx2 = tree.insert(commitment2).unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(tree.size(), 2);

        let root2 = tree.root();

        // Roots should be different
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_merkle_path() {
        // Simple test with just 2 commitments
        let mut tree = MerkleTree::new();

        let commitment1 = [1u8; 32];
        let commitment2 = [2u8; 32];

        tree.insert(commitment1).unwrap();
        tree.insert(commitment2).unwrap();

        // Get path for first commitment
        let path = tree.path(0).unwrap();
        assert_eq!(path.len(), MERKLE_DEPTH);

        // Manually verify: commitment1 is at index 0 (left child)
        // Its sibling at level 0 should be commitment2
        assert_eq!(path[0], commitment2);

        // Verify the path
        let root = tree.root();
        let verified = MerkleTree::verify_path(commitment1, 0, &path, root);

        // Manual verification to debug
        let mut manual_current = commitment1;
        let mut manual_idx = 0u64;
        for (i, sibling) in path.iter().enumerate() {
            let before = manual_current;
            if manual_idx % 2 == 0 {
                manual_current = hash_pair(&manual_current, sibling);
            } else {
                manual_current = hash_pair(sibling, &manual_current);
            }
            if i < 5 {
                eprintln!("Level {}: idx={}, before={}, sibling={}, after={}",
                    i, manual_idx, hex::encode(before), hex::encode(sibling), hex::encode(manual_current));
            }
            manual_idx >>= 1;
        }
        eprintln!("Final manual root: {}", hex::encode(manual_current));
        eprintln!("Tree root:        {}", hex::encode(root));

        assert!(verified, "Path verification failed for commitment at index 0");

        // Wrong commitment should fail
        assert!(!MerkleTree::verify_path([99u8; 32], 0, &path, root));
    }

    #[test]
    fn test_merkle_tree_deterministic() {
        let mut tree1 = MerkleTree::new();
        let mut tree2 = MerkleTree::new();

        let commitments = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        for cm in &commitments {
            tree1.insert(*cm).unwrap();
            tree2.insert(*cm).unwrap();
        }

        // Same commitments should produce same root
        assert_eq!(tree1.root(), tree2.root());
    }
}

use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

/// Frontier represents the rightmost path in the Merkle tree
/// This is an optimization that allows us to store only ~log(n) nodes
/// instead of the full tree of n nodes
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct Frontier {
    /// Frontier nodes at each level
    nodes: Vec<Option<[u8; 32]>>,
}

impl Frontier {
    /// Create a new empty frontier
    pub fn new(depth: usize) -> Self {
        Frontier {
            nodes: vec![None; depth],
        }
    }

    /// Get node at a specific level
    pub fn get(&self, level: usize) -> Option<[u8; 32]> {
        self.nodes.get(level).and_then(|n| *n)
    }

    /// Set node at a specific level
    pub fn set(&mut self, level: usize, node: [u8; 32]) {
        if level < self.nodes.len() {
            self.nodes[level] = Some(node);
        }
    }

    /// Clear node at a specific level
    pub fn clear(&mut self, level: usize) {
        if level < self.nodes.len() {
            self.nodes[level] = None;
        }
    }

    /// Get the depth of the frontier
    pub fn depth(&self) -> usize {
        self.nodes.len()
    }

    /// Get all nodes (for serialization)
    pub fn nodes(&self) -> &[Option<[u8; 32]>] {
        &self.nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frontier_operations() {
        let mut frontier = Frontier::new(5);

        assert_eq!(frontier.depth(), 5);
        assert_eq!(frontier.get(0), None);

        let node = [1u8; 32];
        frontier.set(0, node);
        assert_eq!(frontier.get(0), Some(node));

        frontier.clear(0);
        assert_eq!(frontier.get(0), None);
    }
}

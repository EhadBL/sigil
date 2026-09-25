use crate::envelope::FileRecord;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LEAF_PREFIX: &[u8] = &[0x00];
const NODE_PREFIX: &[u8] = &[0x01];

#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("Index out of bounds: index {index} >= total leaves {total}")]
    IndexOutOfBounds { index: usize, total: usize },
    #[error("Tree is empty")]
    EmptyTree,
    #[error("Invalid hex hash: {0}")]
    InvalidHex(#[from] hex::FromHexError),
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProofStep {
    /// Hex-encoded sibling hash
    pub sibling_hash: String,
    /// True if the sibling is on the left of current node, false if on the right
    pub is_left: bool,
}

/// Complete Merkle Inclusion Proof for a leaf entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub root_hash: String,
    pub steps: Vec<MerkleProofStep>,
}

/// Computes the leaf hash for arbitrary byte payload: H(0x00 || data)
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Computes the interior node hash: H(0x01 || left || right)
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_PREFIX);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// High-performance Binary Merkle Tree with domain separation (RFC 6962 design).
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Levels of the tree from bottom (leaves = level 0) to top (root = levels.last())
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Builds a Merkle Tree from raw leaf byte slices.
    pub fn from_raw_leaves(leaves: &[&[u8]]) -> Self {
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
        Self::from_leaf_hashes(&leaf_hashes)
    }

    /// Builds a Merkle Tree from precomputed leaf hashes.
    pub fn from_leaf_hashes(leaf_hashes: &[[u8; 32]]) -> Self {
        if leaf_hashes.is_empty() {
            let empty_root = hash_leaf(b"");
            return Self {
                levels: vec![vec![empty_root]],
            };
        }

        let mut levels = Vec::new();
        let mut current_level = leaf_hashes.to_vec();
        levels.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    let parent = hash_nodes(&current_level[i], &current_level[i + 1]);
                    next_level.push(parent);
                    i += 2;
                } else {
                    // Odd node promoted directly to the next level
                    next_level.push(current_level[i]);
                    i += 1;
                }
            }
            levels.push(next_level.clone());
            current_level = next_level;
        }

        Self { levels }
    }

    /// Returns the root hash as a 32-byte array.
    pub fn root_bytes(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .copied()
            .unwrap_or_else(|| hash_leaf(b""))
    }

    /// Returns the root hash as a hex string.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root_bytes())
    }

    /// Generates a Merkle inclusion proof for the leaf at `leaf_index`.
    pub fn generate_inclusion_proof(&self, leaf_index: usize) -> Result<MerkleInclusionProof, MerkleError> {
        let total_leaves = self.levels[0].len();
        if leaf_index >= total_leaves {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                total: total_leaves,
            });
        }

        let mut steps = Vec::new();
        let mut idx = leaf_index;

        for level in 0..self.levels.len() - 1 {
            let current_level = &self.levels[level];
            let is_right_child = idx % 2 == 1;

            if is_right_child {
                // Sibling is on the left
                let sibling = current_level[idx - 1];
                steps.push(MerkleProofStep {
                    sibling_hash: hex::encode(sibling),
                    is_left: true,
                });
            } else if idx + 1 < current_level.len() {
                // Sibling is on the right
                let sibling = current_level[idx + 1];
                steps.push(MerkleProofStep {
                    sibling_hash: hex::encode(sibling),
                    is_left: false,
                });
            }
            // If odd node with no sibling at this level, it was promoted; no sibling step needed.

            idx /= 2;
        }

        Ok(MerkleInclusionProof {
            leaf_index,
            total_leaves,
            root_hash: self.root_hex(),
            steps,
        })
    }
}

/// Verifies a Merkle inclusion proof given a raw leaf byte payload and root hash hex.
pub fn verify_inclusion_proof_raw(
    root_hex: &str,
    raw_leaf: &[u8],
    proof: &MerkleInclusionProof,
) -> Result<bool, MerkleError> {
    let leaf_hash = hash_leaf(raw_leaf);
    verify_inclusion_proof_hash(root_hex, &leaf_hash, proof)
}

/// Verifies a Merkle inclusion proof given a 32-byte leaf hash and root hash hex.
pub fn verify_inclusion_proof_hash(
    root_hex: &str,
    leaf_hash: &[u8; 32],
    proof: &MerkleInclusionProof,
) -> Result<bool, MerkleError> {
    if proof.root_hash.to_lowercase() != root_hex.to_lowercase() {
        return Ok(false);
    }

    let mut current_hash = *leaf_hash;

    for step in &proof.steps {
        let sibling_bytes = hex::decode(&step.sibling_hash)?;
        if sibling_bytes.len() != 32 {
            return Ok(false);
        }
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&sibling_bytes);

        if step.is_left {
            current_hash = hash_nodes(&sibling, &current_hash);
        } else {
            current_hash = hash_nodes(&current_hash, &sibling);
        }
    }

    Ok(hex::encode(current_hash).eq_ignore_ascii_case(root_hex))
}

/// Computes a canonical Merkle tree over a list of FileRecords.
pub fn compute_files_merkle_tree(files: &[FileRecord]) -> MerkleTree {
    let leaves: Vec<Vec<u8>> = files
        .iter()
        .map(|f| format!("{}:{}", f.path, f.blake3_hash).into_bytes())
        .collect();
    let leaf_slices: Vec<&[u8]> = leaves.iter().map(|p| p.as_slice()).collect();
    MerkleTree::from_raw_leaves(&leaf_slices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_root_and_inclusion_proof() {
        let data: Vec<&[u8]> = vec![b"file1.js", b"file2.js", b"file3.js", b"sigil.toml", b"README.md"];
        let tree = MerkleTree::from_raw_leaves(&data);
        let root = tree.root_hex();

        // Check inclusion proofs for every leaf
        for (i, item) in data.iter().enumerate() {
            let proof = tree.generate_inclusion_proof(i).unwrap();
            let is_valid = verify_inclusion_proof_raw(&root, item, &proof).unwrap();
            assert!(is_valid, "Leaf {} should be valid in root", i);

            // Tampered leaf must fail
            let tampered_item = b"evil_file.js";
            let tampered_valid = verify_inclusion_proof_raw(&root, tampered_item, &proof).unwrap();
            assert!(!tampered_valid, "Tampered leaf {} must fail", i);
        }
    }
}

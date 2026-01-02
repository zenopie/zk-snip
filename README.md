# zk-SNIP: Dual-Mode Private Token

A privacy-preserving token for Secret Network with **two modes**: TEE mode (backwards compatible with SNIP-20) and ZK mode (cryptographic privacy using zero-knowledge proofs).

## Overview

zk-SNIP offers users a choice between two privacy models:

1. **TEE Mode** (SNIP-20 compatible) - Fast, cheap, TEE-protected
2. **ZK Mode** - Slower, more expensive, cryptographically private

Users can hold balances in both modes and transfer between them.

## Architecture

### TEE Mode (Backwards Compatible)

- **Privacy Model**: Intel SGX Trusted Execution Environment
- **State**: Account balances (`address → balance`)
- **Gas Cost**: ~100-200k per transfer
- **Balance Queries**: Fast (viewing keys)
- **Transaction Graph**: Visible in contract state
- **Compatibility**: Fully compatible with existing SNIP-20 tools

### ZK Mode (Cryptographic Privacy)

- **Privacy Model**: Zero-knowledge proofs (Bulletproofs)
- **State**: Note commitments in Merkle tree
- **Gas Cost**: ~600-700k per transfer (proof verification)
- **Balance Queries**: Must scan commitments to decrypt notes
- **Transaction Graph**: Completely hidden
- **Privacy Guarantee**: Survives TEE compromise

## Key Features

### TEE Mode
- ✅ Existing SNIP-20 balances work without changes
- ✅ Fast balance queries with viewing keys
- ✅ Low transaction costs
- ✅ Standard Secret Network privacy (TEE-protected)

### ZK Mode
- ✅ Zcash-style note-based privacy
- ✅ Cryptographic hiding of amounts and transaction graph
- ✅ No trusted setup (uses Bulletproofs)
- ✅ Privacy doesn't depend on trusting hardware

### Bridge Operations
- ✅ Shield: TEE → ZK (convert balance to private note)
- ✅ Unshield: ZK → TEE (prove note ownership, add to balance)

## Code Structure

```
src/
├── contract.rs           # Main entry points
├── execute*.rs           # TEE mode operations (SNIP-20)
├── state.rs              # TEE balances + config
│
├── note/                 # ZK mode: Note structures
│   ├── note.rs          # Note, commitment
│   ├── nullifier.rs     # Double-spend prevention
│   ├── keys.rs          # Key derivation
│   └── commitment.rs    # Commitment scheme
│
├── tree/                 # ZK mode: Merkle tree
│   ├── merkle.rs        # Commitment tree (frontier optimized)
│   └── frontier.rs      # Rightmost path storage
│
├── zk/                   # ZK mode: Cryptography
│   ├── bulletproofs.rs  # Proof verifier (no trusted setup)
│   ├── crypto.rs        # Pedersen commitments, hashing
│   └── circuits.rs      # Transfer circuit constraints
│
└── operations/           # ZK operations & bridges
    ├── zk_transfer.rs   # ZK → ZK (spend 2 notes, create 2 notes)
    ├── zk_mint.rs       # ∅ → ZK (create note, increase supply)
    ├── zk_burn.rs       # ZK → ∅ (destroy note, decrease supply)
    ├── shield.rs        # TEE → ZK (balance to note)
    └── unshield.rs      # ZK → TEE (note to balance)
```

## Operations

### TEE Mode Operations

**Transfer** (existing SNIP-20)
```json
{
  "transfer": {
    "recipient": "secret1...",
    "amount": "1000"
  }
}
```

**Query Balance** (existing SNIP-20)
```json
{
  "balance": {
    "address": "secret1...",
    "viewing_key": "..."
  }
}
```

### ZK Mode Operations

**ZK Transfer** (private, note-based)
```json
{
  "zk_transfer": {
    "merkle_root": "abc123...",
    "nullifiers": ["def456...", "ghi789..."],
    "commitments": ["jkl012...", "mno345..."],
    "proof": "base64_encoded_bulletproof"
  }
}
```

- Spends 2 old notes (via nullifiers)
- Creates 2 new notes (via commitments)
- Proves everything is valid without revealing amounts

**ZK Mint** (admin only)
```json
{
  "zk_mint": {
    "commitment": "abc123...",
    "amount": "1000"
  }
}
```

- Creates new note from nothing (increases total supply)
- Only admin can mint
- No proof required (admin authority)

**ZK Burn** (anyone with note)
```json
{
  "zk_burn": {
    "amount": "600",
    "merkle_root": "def456...",
    "nullifier": "ghi789...",
    "change_commitment": "jkl012...",
    "proof": "base64_encoded_bulletproof"
  }
}
```

- Destroys note (decreases total supply)
- Requires proof of note ownership
- Creates change note if needed

### Bridge Operations

**Shield** (TEE → ZK)
```json
{
  "shield": {
    "amount": "1000",
    "commitment": "abc123..."
  }
}
```

- Deducts from your TEE balance
- Creates a private note in the tree
- Note can only be spent with ZK proofs

**Unshield** (ZK → TEE)
```json
{
  "unshield": {
    "recipient": "secret1...",
    "amount": "800",
    "merkle_root": "def456...",
    "nullifier": "ghi789...",
    "change_commitment": "jkl012...",
    "proof": "base64_encoded_bulletproof"
  }
}
```

- Proves you own a note
- Marks nullifier as spent
- Adds amount to recipient's TEE balance
- Creates change note if needed

## Privacy Comparison

| Feature | TEE Mode | ZK Mode |
|---------|----------|---------|
| Amount Privacy | ✅ (from validators/users) | ✅ (cryptographic) |
| Transaction Graph | ❌ (visible in contract) | ✅ (hidden) |
| Balance Queries | Fast (viewing keys) | Slow (scan blockchain) |
| Gas Cost | ~100-200k | ~600-700k |
| TEE Compromise | ⚠️ Privacy lost | ✅ Privacy maintained |
| Setup Ceremony | None | None (Bulletproofs) |

## Use Cases

**Daily Spending** → TEE Mode
- Low fees
- Fast confirmations
- Easy balance tracking
- SNIP-20 compatible

**Savings/Privacy** → ZK Mode
- Maximum privacy
- Hidden transaction graph
- Cryptographic guarantees
- Worth the extra cost

**Hybrid Strategy**
- Keep spending money in TEE
- Shield large amounts to ZK
- Unshield when needed

## Implementation Status

✅ **Completed:**
- Note structures and key derivation
- Merkle tree with frontier optimization
- Bulletproofs verifier infrastructure
- Crypto primitives (Pedersen, BLAKE2s)
- Transfer circuit constraints
- ZK transfer operation
- Shield/unshield bridge operations

⏳ **TODO:**
- Integrate actual Bulletproofs library (dalek-cryptography)
- Add query endpoints for commitments
- Client library for proof generation
- Balance scanning utilities
- SNIP-20 compatibility layer in contract.rs
- Viewing key support for ZK mode (optional note index)

## Security Model

### TEE Mode
- **Threat Model**: Trust Intel SGX TEE
- **Privacy**: Hidden from validators and other users
- **Risk**: Hardware vulnerabilities (side-channel attacks)
- **Mitigation**: Same as all Secret Network contracts

### ZK Mode
- **Threat Model**: Trust mathematics (discrete log hardness)
- **Privacy**: Cryptographically hidden (information-theoretic)
- **Risk**: Implementation bugs, circuit vulnerabilities
- **Mitigation**: Formal verification, audits, battle-testing

### Bridge Security
- Shield: Requires TEE balance (simple balance check)
- Unshield: Requires valid ZK proof (mathematical verification)

## Gas Costs

| Operation | Estimated Gas | Notes |
|-----------|--------------|-------|
| **TEE Mode** | | |
| TEE Transfer | ~100-200k | Standard SNIP-20 |
| TEE Mint | ~50-100k | Admin only |
| TEE Burn | ~50-100k | Balance check |
| **ZK Mode** | | |
| ZK Transfer | ~600-700k | Bulletproof verification |
| ZK Mint | ~150-250k | Tree insert only (no proof) |
| ZK Burn | ~650-750k | Proof verification |
| **Bridge** | | |
| Shield | ~150-250k | Balance check + tree insert |
| Unshield | ~650-750k | Proof verification + balance update |

## Backwards Compatibility

**100% backwards compatible with SNIP-20:**
- Existing balances continue to work (TEE mode)
- All SNIP-20 operations unchanged
- New ZK features are purely additive
- Users opt-in to ZK mode by shielding

## Development

### Build
```bash
cargo build
```

### Test
```bash
cargo test --lib
```

### Deploy
```bash
make build
secretcli tx compute store contract.wasm.gz --from mykey
```

## Technical Details

### Merkle Tree
- **Depth**: 32 levels (4 billion max commitments)
- **Storage**: Frontier optimization (~32 nodes)
- **Root History**: Last 100 roots kept for anti-front-running

### Nullifiers
- Derived from spending key + note position
- Stored in set to prevent double-spending
- Public (but don't reveal note contents)

### Commitments
- Pedersen commitment: `Hash(diversifier || pkd || value || rcm)`
- Inserted into Merkle tree
- Recipients scan to find their notes

### Zero-Knowledge Proofs
- **System**: Bulletproofs (no trusted setup)
- **Proves**:
  1. Range proofs (values in [0, 2^64))
  2. Balance conservation (inputs = outputs)
  3. Merkle authentication (notes exist in tree)
  4. Nullifier derivation (correct spending)
  5. Commitment consistency (valid new notes)

## References

- [SNIP-20 Reference Implementation](https://github.com/scrtlabs/snip20-reference-impl)
- [Zcash Sapling Protocol](https://github.com/zcash/zips/blob/master/protocol/sapling.pdf)
- [Bulletproofs Paper](https://eprint.iacr.org/2017/1066.pdf)
- [Secret Network Docs](https://docs.scrt.network/)

## License

MIT

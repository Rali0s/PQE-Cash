# 2. Exact Public/Private Signal Schema

This schema is the canonical V1 signal contract between prover and verifier.

## Public Signals (`length = 7`)
1. `root` (`bytes32` -> `uint256`)
2. `nullifierHash` (`bytes32` -> `uint256`)
3. `recipient` (`address` -> `uint160` -> `uint256`)
4. `relayer` (`address` -> `uint160` -> `uint256`)
5. `fee` (`uint256`)
6. `refund` (`uint256`)
7. `chainId` (`uint256`)

## Private Witness Signals
1. `noteSecret` (`bytes32`)
2. `noteRandom` (`bytes32`)
3. `pathElements[depth]` (`bytes32[]`)
4. `pathIndices[depth]` (`bool[]` or `uint8[]`)

## Constraints (conceptual)
- `nullifierHash == H(domain_nullifier || noteSecret)`
- `commitment == H(domain_commitment || noteSecret || noteRandom)`
- `MerkleVerify(commitment, pathElements, pathIndices) == root`
- public inputs are bound into proof transcript
- chain domain separation includes `chainId`

## Canonical JSON
See: `docs/02-circuit-signals.json`

# Real Proof Generation Plan (BlueARC)

This is the build plan to replace dev proofs (`0x01`) with real ZK proofs.

## 1) Current State
- `PrivacyPool.withdraw(...)` already enforces:
  - known root
  - unspent nullifier
  - verifier call (`verifier.verifyProof(proof, input)`)
- `PqVerifierAdapter` is already in place to route to a real verifier backend.
- Relayer and web transport are production-leaning (encrypted submit, nonce/replay checks).

## 2) Hard Blocker To Resolve First
Current tree hash in pool is `keccak256(left,right)`:
- `<repo-root>/contracts/contracts/PrivacyPool.sol:248`

For real SNARK proving, Keccak Merkle constraints are expensive and will make proving heavy.

Decision required:
1. **Recommended**: migrate to Poseidon-based tree in `PrivacyPoolV2` and circuit.
2. Keep Keccak tree and build heavier circuit (possible, not recommended for operator UX/cost).

Do not start production prover work until this hash decision is finalized.

### Blocker differentiation (why this matters)
#### Option 1: Poseidon tree (`PrivacyPoolV2`) + Poseidon circuit (recommended)
- Fast proving and lower prover memory for Merkle constraints.
- Better UX for browser/mobile proving and faster remote proving.
- Cleaner long-term scaling for relay hosts (more proofs per machine).
- Requires a migration to `PrivacyPoolV2` because on-chain tree hash changes.

#### Option 2: Keep Keccak tree + Keccak circuit (possible)
- No tree migration in contract logic.
- Much heavier circuit constraints (slower proving, larger proving infra).
- Worse operator economics (higher proving cost, more latency).
- More likely to force remote proving even for simple user flows.

## 3) Target Proof Statement
For one withdrawal, prove:
1. Witness commitment is in tree for public `root`.
2. `nullifierHash` is derived from witness secret and domain tag.
3. Public outputs are bound in-circuit:
   - `root`
   - `nullifierHash`
   - `recipient`
   - `relayer`
   - `fee`
   - `refund`
   - `chainId`

Public input vector stays length `7` to match current `withdraw(...)`.

## 4) Components To Build

### A) Circuits + Prover
- New workspace folder: `circuits/`
- Files:
  - `circuits/withdraw.circom` (or Noir equivalent)
  - `circuits/lib/merkle.circom`
  - `circuits/lib/nullifier.circom`
  - `circuits/inputs/example-withdraw.json`
- Build outputs:
  - proving key (`.zkey`/equivalent)
  - verification key JSON
  - Solidity verifier contract artifact

### B) Contract Integration
- Replace dev external verifier with real verifier contract address.
- Keep `PqVerifierAdapter` and set backend mode correctly (`bytes` or `uint`).
- Add integration tests:
  - valid proof withdraw succeeds
  - tampered public inputs fail
  - reused nullifier fails

Current scaffold status:
- `PrivacyPoolV2` contract exists with pluggable tree hasher.
- `IPoseidonHasher` interface exists.
- `PoseidonHasherMock` exists for local-only smoke testing.

#### Adapter/backend matching rules (must match B)
- `PqVerifierAdapter.BackendType.Bytes`:
  - external verifier must implement:
    - `verify(bytes proof, bytes publicInputs) returns (bool)`
  - adapter sends `abi.encode(input)` as `publicInputs`.
- `PqVerifierAdapter.BackendType.Uint`:
  - external verifier must implement:
    - `verifyProof(bytes proof, uint256[] publicInputs) returns (bool)`
  - adapter sends raw `uint256[]`.

If backend type does not match verifier interface, `withdraw` will fail with `invalid proof`.

### C) Relayer Integration
- Validate proof format version before submit.
- Keep size limit (`PROOF_MAX_BYTES`) but set realistic bound from real prover output.
- Add metrics labels for invalid proof reasons.

### D) Web Integration
- Replace `Use Dev Proof (0x01)` path with:
  - load note + Merkle path
  - generate witness
  - call prover (local wasm worker or remote proving service)
  - submit real proof bytes

## 5) Data/Schema Requirements

### Required witness inputs (minimum)
- `noteSecret`
- `noteRandom` (if commitment uses it)
- `pathElements[depth]`
- `pathIndices[depth]`
- public tuple values (`recipient`, `relayer`, `fee`, `refund`, `chainId`, `root`)

### Public signal packing (must match on-chain)
`uint256[7]`:
1. `uint256(root)`
2. `uint256(nullifierHash)`
3. `uint256(uint160(recipient))`
4. `uint256(uint160(relayer))`
5. `fee`
6. `refund`
7. `chainId`

## 6) Security/Operations Requirements
- Domain separation constants for commitment/nullifier.
- Versioned proof format (`proofVersion`) in app/relayer.
- Proving key integrity:
  - pin hash in repo docs
  - verify key hash in CI before deployment
- Ceremony/proving-key provenance documented.

## 7) Execution Plan

### Phase P0: Design Lock
1. Finalize hash strategy (Poseidon recommended).
2. Freeze witness/public schema and domain constants.
3. Define proof encoding (`bytes` vs split structs).

#### P0.3 Proof encoding (`bytes` vs split structs)
Why differ:
- `bytes` encoding:
  - flexible and verifier-agnostic (Groth16/Plonk/STARK wrappers can pack however they need)
  - simpler adapter compatibility and upgrade path
  - easier to transport in relayer/web APIs
- split structs (`a,b,c`/fixed arrays):
  - stricter ABI shape, easier static checks
  - usually tied to one proving system/export format
  - harder to swap proof system later without contract ABI changes

Recommendation for BlueARC:
- Keep contract surface as `bytes proof` (current shape).
- Define canonical `proofVersion` and serialization spec in relayer/web.
- Use adapter backend mode to bridge to concrete verifier ABI.

### Noir equivalent (for circom references)
- Circom `template`/signals ~= Noir `circuit` with typed inputs.
- Circom witness generation ~= Noir `Prover.toml`/input map + backend witness gen.
- Circom Groth16 verifier export ~= Noir backend-specific verifier export (e.g., Barretenberg artifacts).
- Public inputs still must map to the same `uint256[7]` tuple consumed by `withdraw(...)`.

### Phase P1: Circuit + Verifier
1. Implement circuit.
2. Generate verifier contract + keys.
3. Add contract tests using real proof fixtures.

### Phase P2: Relayer + Web
1. Relayer proof version checks and structured errors.
2. Web proof generation flow and progress UX.
3. Remove dev-proof button for production builds.

### Phase P3: Production Hardening
1. Benchmark proving latency + memory.
2. Add failover strategy for proving service.
3. External audit for circuit constraints and verifier wiring.

### Prover hosting options (P2/P3)
1. Local WASM worker (in browser/app):
   - best privacy (no witness leaves client)
   - constrained by device CPU/RAM and longer proving time
2. Remote proving service:
   - low-latency UX with stronger hardware
   - witness leaves client; requires strict transport, auth, and retention policy
3. Hybrid mode:
   - local proving default
   - remote fallback when device capability is insufficient

Suggested production posture:
- Start with hybrid.
- Gate remote prover by policy + explicit user consent.
- Log only proof job metadata, never note/witness material.

## 8) Acceptance Criteria
- Withdraw with real proof confirms on Sepolia.
- Tampered recipient/fee/chainId fails verifier.
- Nullifier replay fails.
- Dev proof path disabled in production build.
- End-to-end tests pass for relayer + web + contracts using real proof fixture.

Additional acceptance checks:
- Adapter backend mode and verifier ABI alignment is verified in deployment checks.
- Poseidon tree/circuit root computation equality is tested against contract vectors.
- Proof encoding version mismatch is rejected by relayer with clear error.

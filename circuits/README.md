# BlueARC Circuits Workspace (Planned)

This folder is reserved for real proof generation artifacts.

Planned structure:
- `withdraw.circom` (or Noir equivalent)
- `lib/` reusable gadgets (Merkle, nullifier, hash adapters)
- `inputs/` deterministic test vectors
- `artifacts/` verifier/proving assets (do not commit toxic waste)

Primary reference:
- `<repo-root>/docs/11-real-proof-generation-plan.md`

Important:
- Keep public signal order exactly aligned with `PrivacyPool.withdraw(...)`.
- Avoid mixing hash functions between contract tree and circuit tree.

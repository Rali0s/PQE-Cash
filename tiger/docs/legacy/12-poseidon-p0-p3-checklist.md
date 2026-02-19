# Poseidon P0-P3 Checklist (Execution Tracker)

## P0 Design Lock
- [ ] P0.1 Decide tree hash strategy: Poseidon `PrivacyPoolV2`.
- [ ] P0.2 Freeze witness/public schema and domain constants.
- [ ] P0.3 Freeze proof encoding as `bytes` + `proofVersion`.
- [ ] P0.4 Choose verifier backend interface mode:
  - [ ] `bytes` backend (`verify(bytes,bytes)`) OR
  - [ ] `uint` backend (`verifyProof(bytes,uint256[])`)
- [ ] P0.5 Decide prover hosting policy (local / remote / hybrid).

## P1 Circuit + Verifier
- [ ] P1.1 Implement Poseidon Merkle circuit.
- [ ] P1.2 Implement nullifier/commitment constraints.
- [ ] P1.3 Generate verifier artifacts and on-chain verifier contract.
- [ ] P1.4 Wire `PqVerifierAdapter` to deployed verifier and set backend.
- [ ] P1.5 Add contract tests with valid + invalid fixtures.

## P2 Relayer + Web
- [ ] P2.1 Add `proofVersion` validation in relayer submit path.
- [ ] P2.2 Set `PROOF_MAX_BYTES` based on real artifact sizes.
- [ ] P2.3 Implement web proof generation path (remove dev button in prod).
- [ ] P2.4 Add structured user errors for proof failures.
- [ ] P2.5 Add telemetry labels for proof failure classes.

## P3 Production Hardening
- [ ] P3.1 Benchmark proving latency (desktop/mobile + remote).
- [ ] P3.2 Remote prover security controls (TLS, auth, no witness retention).
- [ ] P3.3 Multi-relayer + prover failover strategy documented.
- [ ] P3.4 External audit (contracts + circuits + relayer proof flow).

## Acceptance Gates
- [ ] A1 Real proof withdrawal confirmed on Sepolia.
- [ ] A2 Tampered public signal fails verification.
- [ ] A3 Nullifier replay blocked.
- [ ] A4 Dev proof path disabled in production UI build.
- [ ] A5 Adapter backend mismatch test fails fast in deployment checks.

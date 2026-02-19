# 4. BlueARC Product Spec

## Fully On-Chain
- Contract-enforced deposits and withdrawals.
- On-chain root/nullifier checks.
- On-chain proof verifier interface via `PqVerifierAdapter`.
- Protocol fee custody via `ProtocolTreasury` with delayed owner withdrawals.

## Better Privacy
- Fixed denomination pools.
- Relayer-routed withdrawals.
- Encrypted `/submit` payloads with AEAD over a hybrid key negotiated via ECDH + `ML-KEM-768`.
- Signed quote binding and relayer-side signature verification at submit.
- Optional selective disclosure only by note owner.

## Viable Product
- Single asset + single chain initially.
- API + web UI + deploy scripts.
- Production deploy path requires external verifier address + backend mode.

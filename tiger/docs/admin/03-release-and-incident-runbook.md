---
title: Release and Incident Runbook
---

## Release Sequence

1. Run contract tests.
2. Run network preflight.
3. Deploy contracts.
4. Set relayer env (`allowlist`, `poolVersion`, `requiredProofVersion`).
5. Verify `/health` and `/config`.
6. Verify end-to-end deposit/quote/submit/status.

## Incident Response Basics

- Relayer down: fail over to healthy mesh member.
- Signer compromise: disable affected relayer and rotate signer backend.
- Verifier regression: rotate adapter verifier with owner action and event checks.
- Treasury anomaly: pause admin actions, review queued withdrawals, execute governance procedure.

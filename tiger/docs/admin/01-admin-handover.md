---
title: Admin Handover and Continuity
---

This page is written for a new admin taking over BlueARC operations.

## Critical Assets

- Pool owner authority
- Treasury owner authority
- Verifier adapter owner authority
- Relayer signer + signer backend credentials
- Infrastructure credentials (RPC, DB, Redis, hosting)

## Continuity Rules

- Use multisig for ownership in production.
- Keep incident runbooks in source control.
- Rotate relayer signing infrastructure on compromise suspicion.
- Keep allowlists/version policy explicit (`poolVersion`, `proofVersion`).

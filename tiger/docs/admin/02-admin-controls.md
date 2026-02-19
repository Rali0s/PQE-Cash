---
title: Admin Controls Reference
---

Admin UI is exposed at `/admin`.

Pool controls:

- set base relayer fee
- set protocol fee bps
- toggle relayer-only mode
- toggle approved-relayers-only mode
- approve/revoke relayer addresses
- set treasury address

Treasury controls:

- set withdraw delay
- queue withdrawal
- execute withdrawal

Operational guidance:

- Require owner wallet verification before any state-changing action.
- Use queued treasury withdrawals for safety and observability.
- Record tx hashes for every admin action.

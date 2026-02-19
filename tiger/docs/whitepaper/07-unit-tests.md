---
title: G) Published Unit Tests
---

Current suite status: **33 passing**.

Key files:

- `contracts/test/pool.test.js`
- `contracts/test/pool.v2.test.js`
- `contracts/test/pool.security.test.js`
- `contracts/test/adapter.security.test.js`
- `contracts/test/treasury.security.test.js`
- `contracts/test/checklist.expanded.test.js`

Coverage highlights:

- access control
- replay/double-spend prevention
- reentrancy protection
- fee and balance invariants
- root history rotation
- input aliasing guard behavior

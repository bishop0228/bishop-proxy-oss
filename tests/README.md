# bishop-proxy classifier unit tests

This directory contains unit tests for `src/lib/classifier.ts` using vitest.

## MOCK_AI substrate flag

When `env.MOCK_AI === "1"` is set in the Worker environment, the real AI binding
(`env.AI.run`) is bypassed and the classifier returns `{ decision: "allow", category: null }`.
This flag is **never set in production**. It is a named CI substrate relaxation,
disclosed on three surfaces:

1. `src/lib/classifier.ts` — IMPORTANT comment block
2. This file (`tests/README.md`)
3. `docs/dev/bishop-proxy-testing.md`

The tests in this directory do **not** use `MOCK_AI` — they exercise the real
classifier logic by providing stubbed `env.AI.run` implementations.

## Running

```sh
npm test
```

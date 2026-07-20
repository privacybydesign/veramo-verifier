# veramo-verifier — repo notes

Fork of `eduwallet/veramo-verifier`. Runtime is deployed from
`privacybydesign/openid4vc-poc-ops` (`veramo-verifier.tf` + `environments/dev/veramo-verifier/conf/...`).

## Build / lint / test
- `yarn build` — `tsc`.
- `yarn lint` — `eslint`. Note: `src/utils/dumpExpressRoutes.ts` and
  `src/verifier/DCQLSubmission.ts` have pre-existing lint errors on `main`; a
  clean run needs those fixed separately. Lint only your changed files to check
  your own work.
- `yarn test` — `tsx --test src/**/*.test.ts` (node's built-in test runner via
  tsx, no extra deps). Test files live next to the code as `*.test.ts`.

## DID keys
- DID configs are JSON files under `conf/dids/`, loaded by `src/dids/Store.ts`.
- `initialiseKey` generates and persists a key the first time a config is loaded
  (keyed by did/alias in the DB); later boots reload it from the DB.
- To pin a stable key, set `privateKeyFile` in the DID config JSON to a
  PEM-encoded EC private key (resolved relative to `conf/dids/`); the key is
  imported deterministically instead of generated. See `src/dids/importKey.ts`.
- Key crypto is `@muisit/cryptokey`: `Factory.createFromType(type, privHex)`
  takes the raw private scalar as hex (`exportPrivateKey()` produces the same).

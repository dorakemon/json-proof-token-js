# json-proof-token-js

A minimal project demonstrating JSON Web Proof (JWP) logic in Rust, exposed via JavaScript/TypeScript bindings. This setup is based on the [json-proof-token](https://github.com/Cybersecurity-LINKS/json-proof-token) repository.

## Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs). Make sure you have the `wasm32-unknown-unknown` target installed:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- **Bun** (optional): Install from [bun.sh](https://bun.sh).
- **Package manager** (recommended): [@antfu/ni](https://www.npmjs.com/package/@antfu/ni)
  ```bash
  npm i -g @antfu/ni
  ```
  Or feel free to use `npm`, `pnpm`, or `yarn`.

## Scripts

- **Build**: 
  ```bash
  nr build
  ```
  (Compiles the Rust code to WASM and bundles the JS.)

- **Test**: 
  ```bash
  nr test
  ```
  This runs Rust tests first, then JavaScript tests.

- **Check (format & lint)**: 
  ```bash
  nr check
  ```

## Development Workflow

1. Write and run Rust tests in `src/*.rs` (or the `tests` module).
2. Use `nr build` to rebuild the WASM package.
3. Write and run JavaScript tests in `test/*.test.ts`.
4. Once everything passes, we can publish `nr build && npm publish`.

Happy coding!
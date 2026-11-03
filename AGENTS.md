# Working in this repository

## Development process

This project is developed with agentic coding. Work is delivered in large,
outcome-sized pull requests, not small granular ones:

- One PR delivers one testable outcome — usually a milestone or a large slice
  of one from [ROADMAP.md](ROADMAP.md).
- Inside a PR, commits are logical steps; there are no preparatory PRs.
  Refactors, scaffolding and dependency changes go into the PR that needs
  them.
- A PR is ready when its outcome is proven by tests in CI — a milestone's
  "Done when" criteria, or new end-to-end tests for a slice of one.
- Self-reviewed before opening: build, lint, tests and a review pass.
- Split only for parallel workstreams that touch separate areas, or for a
  shared foundation that other in-flight work depends on.
- PR descriptions state what is delivered, how it was verified and what is
  left for later.

## Commits

- Author: the repository owner's configured identity.
- No trailers of any kind in commit messages (no `Co-authored-by`,
  `Signed-off-by` or similar).

## Commands

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
cargo test                      # end-to-end tests run on macOS arm64 only
python3 tools/gen-abi.py        # regenerate crates/abi/src/generated.rs
```

These are what CI runs. On a non-macOS host the macOS-specific code is
type-checked by the `aarch64-apple-darwin` clippy run and the kernel crate's
unit tests run natively; end-to-end behaviour is verified in CI on macOS
runners. The end-to-end tests build the guests into `target/guests` and need
`clang` from the Xcode command line tools.

The hypervisor backend needs the hypervisor entitlement and a bare-metal
Apple Silicon host. Its end-to-end tests (`hv_*`) sign a copy of `fwe`
themselves and run wherever `cargo test` runs on such a Mac; in the hosted
CI jobs they skip, and the self-hosted `hypervisor` job runs them; set
`FWE_NO_HV=1` to skip them on a Mac that could run them. To run a
low-linked program by hand:

```sh
cargo build --release -p fwe
codesign --sign - --entitlements hypervisor.entitlements --force target/release/fwe
target/release/fwe ./program-linked-low
```

## Documents

Each document has one job; do not duplicate content across them.

| Document | Holds |
|---|---|
| [README.md](README.md) | What the project is, a short status, how to run and test it |
| [PLAN.md](PLAN.md) | Goal, approach, scope, principles, how progress is measured |
| [ROADMAP.md](ROADMAP.md) | Milestones with checklists, "Done when" criteria and status |
| [docs/architecture.md](docs/architecture.md) | How each part works, and the current limitations |
| [docs/hypervisor.md](docs/hypervisor.md) | The hypervisor backend, how to run it, and its CI arrangement |
| `guests/*/README.md` | Provenance and licenses of vendored test fixtures |

A PR that changes behaviour updates them in the same PR: tick the roadmap
item its tests prove, remove a lifted limitation from
`docs/architecture.md` and the roadmap, and keep module-level doc comments
in the code consistent with what the code now does.

## Conventions

- Every `unsafe` block has a `// SAFETY:` comment.
- Linux ABI values live in `crates/abi`; host translation lives in
  `crates/kernel/src/host.rs`.
- New system calls get a unit test in the kernel crate where possible, and a
  guest program plus end-to-end test when behaviour depends on the backend.
- Vendored binaries under `guests/` are unmodified, with provenance and
  license recorded in that directory's README.
- Treat implementation problems as things to solve, not as blockers.
- A process running a Hypervisor.framework VM must never end, exec or fork
  with the VM alive, and tests run one VM process at a time: abnormal VM
  teardown took the development machine down twice (see
  [docs/hypervisor.md](docs/hypervisor.md)).

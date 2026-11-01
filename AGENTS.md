# Working in this repository

## Development process

This project is developed with agentic coding. Work is delivered in large,
outcome-sized pull requests, not small granular ones:

- One PR delivers one testable outcome — usually a milestone or a large slice
  of one from [ROADMAP.md](ROADMAP.md).
- Inside a PR, commits are logical steps; there are no preparatory PRs.
  Refactors, scaffolding and dependency changes go into the PR that needs
  them.
- A PR is ready when its milestone's "Done when" criteria pass in CI.
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

On a non-macOS host, the macOS-specific code is type-checked with the
`aarch64-apple-darwin` clippy run; end-to-end behaviour is verified in CI on
macOS runners.

## Conventions

- Every `unsafe` block has a `// SAFETY:` comment.
- Linux ABI values live in `crates/abi`; host translation lives in
  `crates/kernel/src/host.rs`.
- New system calls get a unit test in the kernel crate where possible, and a
  guest program plus end-to-end test when behaviour depends on the backend.
- Treat implementation problems as things to solve, not as blockers.

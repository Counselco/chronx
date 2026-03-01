# Contributing to ChronX

Welcome, and thank you for your interest in contributing to ChronX — an open protocol for long-horizon financial promises. ChronX is built in public and every contribution, whether a bug fix, documentation improvement, or new feature, helps advance a more trustworthy financial future.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Running a Local Node](#running-a-local-node)
- [Code Style](#code-style)
- [Branch Naming](#branch-naming)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Code of Conduct](#code-of-conduct)

---

## Prerequisites

- **Rust (stable)** — Install via [rustup.rs](https://rustup.rs). The workspace uses stable Rust; no nightly features required.
- **cargo** — Included with Rust.
- **Git**

Optional for GUI wallet development:
- **Node.js** (for Trunk/Tauri tooling)
- **Android SDK + NDK + JDK 21** (for Android builds)

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Counselco/chronx.git
cd chronx

# Build all workspace crates
cargo build --workspace

# Verify everything compiles cleanly
cargo check --workspace
```

---

## Running Tests

The test suite lives in library code (`src/` modules, not integration tests). Run all tests with:

```bash
cargo test --lib
```

All 45 tests must pass before any PR is merged. The test suite includes:

- Genesis supply verification (confirms 8,270,000,000 KX total)
- Treasury lock ID uniqueness (100 unique deterministic IDs)
- State engine: honest claim flow, fraudulent claim slashing
- Consensus validation rules for all transaction types

To run tests for a specific crate:

```bash
cargo test --lib -p chronx-state
cargo test --lib -p chronx-genesis
```

---

## Running a Local Node

```bash
# Build the node binary
cargo build --release -p chronx-node

# Run with ephemeral genesis (development only — do not use in production)
./target/release/chronx-node \
  --data-dir ~/.chronx/dev-data \
  --rpc-addr 127.0.0.1:8545 \
  --p2p-listen /ip4/0.0.0.0/tcp/7777

# In another terminal, test the RPC
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chronx_getVersion","params":[],"id":1}'
```

---

## Code Style

ChronX follows standard Rust conventions.

**Formatting:**
```bash
cargo fmt --all
```
All PRs must pass `cargo fmt --check --all`. Format your code before submitting.

**Linting:**
```bash
cargo clippy --workspace -- -D warnings
```
All PRs must pass clippy with no warnings. If a warning requires suppression, use `#[allow(...)]` with a comment explaining why.

**Documentation:**
- Public types and functions must have `///` doc comments.
- Module-level docs use `//!`.
- Keep comments accurate — outdated comments are worse than no comments.

**General principles:**
- Prefer explicit over clever.
- `unwrap()` and `expect()` are acceptable in test code and genesis (one-time-run) code. Avoid them in consensus-critical paths.
- All new fields on consensus types must use `#[serde(default)]` for backward compatibility.
- Never remove serialized fields from `Account`, `TimeLockContract`, or `Transaction` — mark them deprecated instead.

---

## Branch Naming

Use the following prefixes:

| Prefix | Use for |
|---|---|
| `feature/` | New functionality |
| `fix/` | Bug fixes |
| `docs/` | Documentation only |
| `refactor/` | Code restructuring without behavior change |
| `test/` | New or updated tests |
| `chore/` | Tooling, CI, dependency updates |

Examples: `feature/email-lock-activation`, `fix/cancel-timelock-window`, `docs/rpc-api-reference`

---

## Pull Request Process

1. **Create your branch** from `main`.
2. **Implement your changes** following the code style guidelines above.
3. **Update `CHANGES.md`** — add your changes under the `[Unreleased]` section.
4. **Run the full check suite** locally:
   ```bash
   cargo fmt --check --all
   cargo clippy --workspace -- -D warnings
   cargo test --lib
   ```
5. **Open a PR** against `main`. Use the PR template. Describe *what* changed and *why*.
6. **Reference any related issues** using `Closes #123` or `Fixes #123`.
7. A maintainer will review your PR. Please be responsive to feedback.
8. Once approved and CI passes, a maintainer will merge.

**Breaking changes** (consensus-layer modifications that require re-genesis or fork) must be discussed in an issue before any implementation work begins.

---

## Issue Reporting

**Bug reports:** Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include your OS, Rust version, node version, and full logs where relevant.

**Feature requests:** Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md). Describe the problem you are trying to solve, not just the solution.

**Security vulnerabilities:** Do NOT open a public issue. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Code of Conduct

ChronX is an open protocol and we want it to remain a welcoming place for contributors of all backgrounds and experience levels.

- Be respectful. Disagreement is fine; disrespect is not.
- Assume good intent from other contributors.
- Constructive criticism is valued. Personal attacks are not.
- Keep discussions focused on the technical merits of proposals.
- Maintainers reserve the right to close or remove contributions that are offensive, off-topic, or otherwise harmful to the project.

If you experience or witness behaviour that violates these expectations, contact the maintainers directly.

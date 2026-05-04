# Contributing to PhantomVault

Thank you for your interest in contributing.

## Before You Start

Read [docs/SECURITY.md](docs/SECURITY.md) and [docs/AUDIT_PLAN.md](docs/AUDIT_PLAN.md).
Understand the distinction between the TCB and the orchestration layer before making any changes.

## The Two Categories of Contribution

### Changes to phantom_core/src/ — Security Critical

Any change to the six TCB files (memory.rs, crypto.rs, header.rs, input.rs, hmac.rs, shamir.rs) is a potential security change. These require:

- A clear description of what security property the change affects
- All existing tests continuing to pass
- New tests covering the changed behaviour
- Zero clippy warnings with `-D warnings`
- A justification for any use of `unsafe`

Do not change cryptographic primitives, key sizes, KDF parameters, or the vault format without opening a discussion issue first.

### Changes to phantomvault/ — Orchestration Layer

Python changes to the CLI, vault lifecycle, stealth, or container handling are UX changes. They still require passing tests and clean linting, but do not require the security justification that TCB changes do.

## Development Setup

```bash
bash scripts/setup.sh
source .venv/bin/activate
bash scripts/check_env.sh
```

## Running Tests

```bash
# Rust unit tests
cargo test --manifest-path phantom_core/Cargo.toml -- --test-threads=1

# Integration tests
cargo test --manifest-path phantom_core/Cargo.toml --test integration_test -- --test-threads=1

# Linting — zero warnings required
cargo clippy --manifest-path phantom_core/Cargo.toml -- -D warnings
```

## Pull Request Requirements

- All tests pass
- `cargo clippy -- -D warnings` produces zero output
- Commit messages follow the format: `type(scope): description`
  Examples: `fix(crypto): correct nonce construction for ChaCha20`
  `feat(cli): add about command`
  `docs(security): update hibernation limitation`
- One logical change per pull request

## Reporting Security Issues

Do not open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).

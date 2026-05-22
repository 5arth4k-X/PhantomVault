# Contributing to PhantomVault

Thank you for your interest.

---

## Read This First

Before making any change, understand the two-layer architecture:

- **`phantom_core/src/`** — The Rust Trusted Computing Base. A bug here is a security vulnerability.
- **`phantomvault/`** — The Python orchestration layer. A bug here is a UX defect.

Read [docs/SECURITY.md](docs/SECURITY.md) and [docs/AUDIT_PLAN.md](docs/AUDIT_PLAN.md) before touching `phantom_core`.

---

## Development Setup

```bash
git clone https://github.com/5arth4k-X/PhantomVault
cd PhantomVault
bash scripts/setup.sh
source .venv/bin/activate
bash scripts/check_env.sh
```

---

## Running Tests

```bash
# Rust unit tests (runs Argon2id — takes a few minutes)
cargo test --manifest-path phantom_core/Cargo.toml -- --test-threads=1

# Integration tests
cargo test --manifest-path phantom_core/Cargo.toml --test integration_test -- --test-threads=1

# Linting — zero warnings required
cargo clippy --manifest-path phantom_core/Cargo.toml -- -D warnings

# Dependency audit
cargo deny --manifest-path phantom_core/Cargo.toml check
```

---

## Two Types of Contribution

### Changes to `phantom_core/src/` — Security Critical

Any change to the six TCB files requires:

- [ ] Clear description of which security property the change affects
- [ ] All existing tests still pass
- [ ] New tests covering the changed behaviour
- [ ] Zero clippy warnings (`-D warnings`)
- [ ] Justification for any use of `unsafe`

> [!WARNING]
> Do not change cryptographic primitives, key sizes, KDF parameters, or the vault binary format without opening a discussion issue first.

### Changes to `phantomvault/` — Orchestration Layer

Python changes to the CLI, vault lifecycle, stealth, or container handling require:

- [ ] Tests pass
- [ ] No new imports that cross the key boundary
- [ ] `ruff` and `black` formatting pass

---

## Pull Request Requirements

- All CI checks pass (Rust tests, clippy, dependency audit, Python build)
- Commit messages follow the format: `type(scope): description`

### Commit Types

| Type | When to use |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `security` | Security fix — use for any TCB change |
| `docs` | Documentation only |
| `test` | Adding or fixing tests |
| `ci` | CI/CD workflow changes |
| `chore` | Maintenance, version bumps, dependency updates |

### Examples

```bash
fix(crypto): correct nonce construction for ChaCha20
feat(cli): add about command
security(header): verify HMAC using raw bytes not re-serialised struct
docs(threat-model): add T3.5 OS compromise tier
test(shamir): add edge case for threshold equals total shares
```

---

## Reporting Security Issues

> [!CAUTION]
> Do **not** open a public issue for security vulnerabilities.See [SECURITY.md](SECURITY.md) for the private disclosure process.

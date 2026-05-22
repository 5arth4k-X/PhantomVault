# PhantomVault — Versioning Strategy

## Version Format

`MAJOR.MINOR.PATCH` following [Semantic Versioning](https://semver.org/).

| Increment | When | Old vaults |
|---|---|---|
| `MAJOR` | Vault binary format incompatible change | Cannot be opened — migration tool provided |
| `MINOR` | New features, backward compatible | Still open correctly |
| `PATCH` | Bug fixes and security patches | No behaviour change |

---

## Branch Strategy

| Branch | Purpose | Rules |
|---|---|---|
| `main` | Releases only | Always passes CI. No direct commits. |
| `develop` | Active development | All PRs merge here first |
| `feature/*` | Individual features | Branch from develop, merge back to develop |
| `hotfix/*` | Critical security fixes | Branch from main, merge to main then back-merge to develop |

---

## How to Release a New Version

### Step 1 — Update version numbers (three files)

```bash
# phantom_core/Cargo.toml
version = "1.0.1"

# pyproject.toml
version = "1.0.1"

# phantomvault/__init__.py
__version__ = "1.0.1"
```

### Step 2 — Update CHANGELOG.md

Move items from `[Unreleased]` to a new dated section:

```markdown
## [1.0.1] — 2026-MM-DD

### Fixed
- Description of what was fixed
```

### Step 3 — Run full test suite

```bash
cargo test --manifest-path phantom_core/Cargo.toml -- --test-threads=1
cargo clippy --manifest-path phantom_core/Cargo.toml -- -D warnings
cargo deny --manifest-path phantom_core/Cargo.toml check
```

All checks must pass before tagging.

### Step 4 — Commit and tag

```bash
git add phantom_core/Cargo.toml pyproject.toml phantomvault/__init__.py CHANGELOG.md
git commit -m "chore: release v1.0.1"
git tag -a v1.0.1 -m "Release v1.0.1 — brief description"
git push origin main
git push origin v1.0.1
```

### Step 5 — Create GitHub Release

After CI passes on the tag, go to GitHub → Releases → Create release from tag.
Copy the CHANGELOG entry for this version into the release notes.

---

## Vault Format Versioning

The vault container format is versioned **independently** from the software version.

The magic bytes in the header encode the format version:

| Magic bytes | Format version |
|---|---|
| `PHVLT100` | v1.0 — current |
| `PHVLT200` | v2.0 — future |

If the vault format ever changes in a way that requires re-encryption of existing vaults:
- Magic bytes change to `PHVLT200`
- A migration tool is provided that opens v1.0 vaults and re-encrypts them as v2.0
- Software version and format version are always independent

---

## Security Patch Process

When a security vulnerability is discovered and confirmed:

1. Fix is developed in a **private** branch
2. CI runs on the fix privately before disclosure
3. Coordinated disclosure with the reporter
4. Fix merged, PATCH version bumped, release tagged
5. `SECURITY.md` and `docs/SECURITY.md` updated with CVE if assigned
6. `deny.toml` advisory ignore list updated if needed
7. Release notes explicitly mention the security fix

---

## Dependency Update Policy

| Dependency type | Update frequency | Review required |
|---|---|---|
| Security patch | Immediately on advisory | Manual code review |
| Minor version | Monthly | Check changelog |
| Major version | Evaluate per release | Full review + tests |

Run `cargo deny check advisories` after every dependency update before pushing.

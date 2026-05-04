# PhantomVault Versioning Strategy

## Version format

MAJOR.MINOR.PATCH following Semantic Versioning.

- MAJOR: Vault format incompatible change. Old vaults cannot be opened.
- MINOR: New features, backward compatible. Old vaults still open.
- PATCH: Bug fixes and security patches. No behaviour change.

## Branch strategy
main        — release branch. Only tagged releases. Always passes CI.
develop     — active development. PRs merge here first.
feature/*   — individual feature branches, merge into develop.
hotfix/*    — critical fixes, merge into main directly, then back-merge to develop.
## How to release a new version

Step 1 — Update version numbers in three files:

```bash
# phantom_core/Cargo.toml
version = "1.0.1"

# pyproject.toml
version = "1.0.1"

# phantomvault/__init__.py
__version__ = "1.0.1"
```

Step 2 — Update CHANGELOG.md. Move items from [Unreleased] to a new dated section.

Step 3 — Commit the version bump:

```bash
git add -A
git commit -m "chore: release v1.0.1"
```

Step 4 — Tag the release:

```bash
git tag -a v1.0.1 -m "Release v1.0.1 — brief description of what changed"
git push origin main
git push origin v1.0.1
```

Step 5 — GitHub automatically runs CI on the tag. After CI passes, create a GitHub Release from the tag in the GitHub UI.

## Vault format versioning

The vault container format is versioned separately from the software version. The magic bytes in the header contain the format version: `PHVLT100` means PhantomVault format 1.0.0.

If the vault format ever changes in a way that requires re-encryption of existing vaults, the magic bytes change (`PHVLT200`) and a migration tool is provided. Software version and format version are independent.

## Security patch process

If a security vulnerability is discovered:

1. Fix is developed in a private branch.
2. CI runs on the fix privately.
3. Coordinated disclosure happens.
4. Fix is merged, PATCH version bumped, release tagged.
5. SECURITY.md updated with the CVE if one is assigned.

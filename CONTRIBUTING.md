# Contributing to ZeroTraceMsg

## Branch Strategy

```
main
 └── dev
      ├── feature/<name>
      └── fix/<name>
```

| Branch | Purpose | Branches from | Merges into |
|--------|---------|---------------|-------------|
| `main` | Stable, production-ready | — | — |
| `dev` | Integration — all features land here first | `main` | `main` |
| `feature/<name>` | New feature | `dev` | `dev` |
| `fix/<name>` | Bug fix | `dev` | `dev` |
| `hotfix/<name>` | Critical production fix | `main` | `main` + `dev` |

---

## Workflow

### Starting a new feature or fix

```bash
git checkout dev
git pull origin dev
git checkout -b feature/message-padding   # or fix/contacts-encryption
```

### Making changes

Commit often with clear messages:
```bash
git commit -m "feat: add message padding to fixed 4KB blobs"
git commit -m "fix: encrypt contacts file at rest"
git commit -m "test: add padding round-trip test"
```

Prefixes:
- `feat:` — new feature
- `fix:` — bug fix
- `test:` — adding or updating tests
- `refactor:` — code change with no behavior change
- `docs:` — documentation only

### Opening a PR

```bash
git push origin feature/message-padding
```

Then open a PR on GitHub: `feature/message-padding → dev`

PR checklist:
- [ ] CI passes (all tests green)
- [ ] Coverage does not decrease
- [ ] No compiler warnings added

### Releasing to main

When `dev` is stable and tested, open a PR: `dev → main`

This is the only way code reaches `main`. Direct pushes to `main` are blocked.

### Hotfix (production emergency)

```bash
git checkout main
git checkout -b hotfix/crash-on-empty-blob
# fix the issue
git push origin hotfix/crash-on-empty-blob
# PR into main AND into dev
```

---

## Branch Protection (set on GitHub)

**`main`:**
- Require PR before merging
- Require CI to pass
- No direct pushes

**`dev`:**
- Require PR before merging
- Require CI to pass
- No direct pushes

---

## Planned Features (branch from `dev`)

| Branch | Feature |
|--------|---------|
| `feature/message-padding` | Pad all blobs to fixed 4KB — hides message length |
| `feature/tls-transport` | Wrap server TCP in TLS — protects session tokens |
| `feature/contacts-encryption` | Encrypt contacts file at rest |
| `feature/delivery-confirmation` | Notify sender when message is retrieved |
| `feature/post-quantum-keys` | Replace ECDH with ML-KEM for key exchange |

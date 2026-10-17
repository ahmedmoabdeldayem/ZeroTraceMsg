# Contributing to ZeroTraceMsg

## Branch Strategy

All work branches directly from `main` and merges back into `main`.

| Branch | Purpose | Branches from | Merges into |
|--------|---------|---------------|-------------|
| `main` | Stable, production-ready | — | — |
| `feature/<name>` | New feature | `main` | `main` |
| `fix/<name>` | Bug fix | `main` | `main` |
| `hotfix/<name>` | Critical production fix | `main` | `main` |

---

## Workflow

### Starting a new feature or fix

```bash
git checkout main
git pull origin main
git checkout -b feature/message-padding   # or fix/contacts-encryption
```

### Making changes

Commit with clear, concise messages:
```bash
git commit -m "pad all blobs to fixed 4KB before encrypting"
git commit -m "encrypt contacts file at rest"
git commit -m "add padding round-trip test"
```

### Opening a PR

```bash
git push origin feature/my-feature
```

Then open a PR on GitHub: `feature/my-feature → main`

PR checklist:
- [ ] CI passes (all tests green)
- [ ] Coverage does not decrease
- [ ] No compiler warnings added

### Hotfix (production emergency)

```bash
git checkout main
git checkout -b hotfix/crash-on-empty-blob
# fix the issue
git push origin hotfix/crash-on-empty-blob
# CI opens a PR to main automatically
```

---

## Branch Protection (set on GitHub)

**`main`:**
- Require PR before merging
- Require CI to pass (build, test, sanitize, lint, coverage)
- No direct pushes

---

## Planned Features

| Branch | Feature |
|--------|---------|
| `feature/contacts-encryption` | Encrypt contacts file at rest |

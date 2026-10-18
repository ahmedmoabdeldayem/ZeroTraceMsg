## What this PR does

<!-- One paragraph describing the change and why it is needed. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behaviour change)
- [ ] Docs / config only

## Security impact

<!-- Does this touch the crypto pipeline, key handling, wire protocol, or TLS?
     If yes, describe what you changed and why it is safe. Write "None" if not applicable. -->

## Test plan

- [ ] `make test` passes
- [ ] `make sanitize` passes (ASan + UBSan)
- [ ] New tests added for new code paths
- [ ] `make format-check` passes

## Checklist

- [ ] Commit messages are concise and describe the *why*, not the *what*
- [ ] No secrets, keys, or identity files committed
- [ ] `zerotrace.conf` updated if new config keys were added
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

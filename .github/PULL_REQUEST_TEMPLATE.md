## Description

Briefly describe what this PR changes and why.

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (consensus change, re-genesis required, or API change)
- [ ] Documentation update
- [ ] Refactor (no behaviour change)
- [ ] Dependency update

## Testing Done

Describe how you tested this change. Include any relevant test commands.

```bash
cargo test --lib -p <crate-name>
```

## Checklist

- [ ] `cargo test --lib --workspace` passes
- [ ] `cargo fmt --check --all` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `CHANGES.md` updated under `[Unreleased]`
- [ ] Public types/functions have `///` doc comments
- [ ] If this is a consensus change: discussed in a related issue first

## Related Issues

Closes # (issue number)

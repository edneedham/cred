# CI/CD Integration

cred is designed to work well in automated environments. All commands support flags for non-interactive use.

## Automation Flags

| Flag                | Description                         |
| ------------------- | ----------------------------------- |
| `--json`            | Machine-readable JSON output        |
| `--non-interactive` | Fail instead of prompting for input |
| `--dry-run`         | Preview changes without applying    |

## Setting Up Targets in CI

```bash
cred target set github \
  --token "$CRED_GITHUB_TOKEN" \
  --non-interactive
```

Then push secrets:

```bash
cred push github --non-interactive
```

## Example: GitHub Actions

Use cred in a workflow to sync secrets:

```yaml
name: Sync Secrets

on:
    workflow_dispatch: # Manual trigger

jobs:
    sync:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4

            - name: Install cred
              run: cargo install cred

            - name: Configure target
              run: |
                  cred target set github \
                    --token "${{ secrets.CRED_GITHUB_TOKEN }}" \
                    --non-interactive

            - name: Push secrets
              run: cred push github --non-interactive --json
```

> **Note:** This requires your vault to be accessible in CI. Consider whether this fits your security model.

## Machine-Readable Output

All commands support `--json` for parsing:

```bash
cred push github --non-interactive --json
```

```json
{
    "success": true,
    "pushed": ["DATABASE_URL", "API_KEY"],
    "skipped": [],
    "errors": []
}
```

## Dry Run in CI

Use `--dry-run` to validate changes in PR checks:

```bash
cred push github --dry-run --json
```

This reports what would change without making modifications.

## Best Practices

1. **Use dedicated tokens** — Create a separate PAT for CI with minimal permissions
2. **Prefer dry-run in PRs** — Validate changes before merging
3. **Log JSON output** — Makes debugging easier
4. **Fail fast** — Always use `--non-interactive` in CI

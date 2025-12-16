# prune

Delete secrets from a target platform. This is a **remote-only** operation — it does not affect your local vault.

## Basic Usage

Remove a specific key from a target:

```bash
cred prune github JWT_SECRET --yes
```

Remove multiple keys:

```bash
cred prune github JWT_SECRET OLD_API_KEY --yes
```

## Dry Run

Preview what will be deleted:

```bash
cred prune github JWT_SECRET --dry-run
```

## Prune All

Remove all known keys from a target:

```bash
cred prune github --all --yes
```

This removes all secrets that cred has pushed to this target.

## Options

| Flag        | Description                   |
| ----------- | ----------------------------- |
| `--dry-run` | Preview without deleting      |
| `--yes`     | Confirm destructive operation |
| `--all`     | Prune all known secrets       |
| `--json`    | Machine-readable output       |

## Safety

⚠️ **Destructive operations require `--yes`** unless using `--dry-run`.

This prevents accidental deletion of production secrets.

## Local vs Remote

| Operation                   | Command                        |
| --------------------------- | ------------------------------ |
| Delete from vault (local)   | `cred secret remove KEY --yes` |
| Delete from target (remote) | `cred prune github KEY --yes`  |
| Delete from both            | Run both commands              |

## Workflow Example

Remove a secret completely:

```bash
# Remove from GitHub first
cred prune github OLD_SECRET --yes

# Then remove from local vault
cred secret remove OLD_SECRET --yes
```

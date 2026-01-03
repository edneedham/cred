# secret

Manage secrets in your local vault.

## set

Add or update a secret:

```bash
cred secret set DATABASE_URL "postgres://user:pass@localhost:5432/db"
```

With a description:

```bash
cred secret set API_KEY "sk-xxx" --description "OpenAI production key"
cred secret set CERT_PEM "-----BEGIN..." -d "TLS certificate"
```

In a specific environment:

```bash
cred secret set DATABASE_URL "postgres://prod..." --env prod
```

### Format Detection

cred auto-detects the format of your secrets:

| Format      | Detection                | Example            |
| ----------- | ------------------------ | ------------------ |
| `pem`       | Starts with `-----BEGIN` | Certificates, keys |
| `json`      | Valid JSON object/array  | `{"key": "value"}` |
| `base64`    | Single-line base64       | `SGVsbG8gV29ybGQ=` |
| `multiline` | Contains newlines        | Multi-line text    |
| `raw`       | Default                  | Single-line text   |

Override auto-detection:

```bash
cred secret set MY_KEY "value" --format json
```

---

## get

Retrieve a secret value:

```bash
cred secret get JWT_SECRET
```

From a specific environment:

```bash
cred secret get JWT_SECRET --env prod
```

With full metadata:

```bash
cred secret get JWT_SECRET --json
```

```json
{
    "data": {
        "key": "JWT_SECRET",
        "value": "super-secret",
        "format": "raw",
        "created_at": "2025-12-11T12:00:00Z",
        "updated_at": "2025-12-11T12:00:00Z",
        "description": null
    }
}
```

---

## list

List all secrets in the vault:

```bash
cred secret list
```

Output:

```
Vault content:
  API_KEY = ***** (OpenAI production key)
  JWT_SECRET = *****
```

List secrets in a specific environment:

```bash
cred secret list --env prod
```

Descriptions are shown inline when present.

---

## remove

Delete a secret from the local vault:

```bash
cred secret remove JWT_SECRET --yes
```

From a specific environment:

```bash
cred secret remove JWT_SECRET --env prod --yes
```

Output:

```
✓ Removed 'JWT_SECRET' from local vault (3 days old)
```

> **Note:** This only removes from the local vault. To delete from a target, use [`cred prune`](./prune.md).

---

## describe

Update a secret's description:

```bash
cred secret describe API_KEY "Updated: rotating quarterly"
```

Clear a description:

```bash
cred secret describe API_KEY
```

---

## history

View the version history of a secret:

```bash
cred secret history DATABASE_URL
```

Output:

```
History for 'DATABASE_URL' in env 'default':

  [current] 2025-01-03 14:30:00 (manual)
  [0] 2025-01-02 10:15:00 (manual)
  [1] 2025-01-01 09:00:00 (manual)

Use 'cred secret rollback DATABASE_URL --version <N>' to restore
```

From a specific environment:

```bash
cred secret history DATABASE_URL --env prod
```

cred keeps up to 10 previous versions of each secret.

---

## rollback

Restore a secret to a previous version:

```bash
cred secret rollback DATABASE_URL --version 0 --yes
```

The `--version` flag specifies which historical version to restore (0 = most recent previous value).

From a specific environment:

```bash
cred secret rollback DATABASE_URL --version 0 --env prod --yes
```

Preview before rolling back:

```bash
cred secret rollback DATABASE_URL --version 0 --dry-run
```

> **Note:** Rollback is a destructive operation and requires `--yes` to confirm.

---

## import

Import `KEY=VALUE` pairs from a .env file:

```bash
cred import .env
```

Import to a specific environment:

```bash
cred import prod.env --env prod
```

Existing keys are skipped by default to keep imports non-destructive.

Overwrite existing keys:

```bash
cred import .env --overwrite
```

Preview without writing:

```bash
cred import .env --dry-run
```

---

## export

Write vault contents to a .env file:

```bash
cred export .env.backup
```

Export from a specific environment:

```bash
cred export prod.env --env prod
```

Keys are sorted alphabetically. Existing files are preserved unless forced:

```bash
cred export .env --force
```

Preview:

```bash
cred export .env --dry-run
```

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

Descriptions are shown inline when present.

---

## remove

Delete a secret from the local vault:

```bash
cred secret remove JWT_SECRET --yes
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

## import

Import `KEY=VALUE` pairs from a .env file:

```bash
cred import .env
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

Keys are sorted alphabetically. Existing files are preserved unless forced:

```bash
cred export .env --force
```

Preview:

```bash
cred export .env --dry-run
```

# Sources

Sources are platforms that can **programmatically generate credentials**. Unlike targets (which only receive secrets), sources create new API keys on demand.

## Why Use Sources?

Instead of manually creating API keys in a web dashboard and copy-pasting them, sources let you:

-   Generate keys directly from the command line
-   Automatically store them in your vault with proper metadata
-   Track which keys came from which source
-   Revoke all generated keys at once when needed

## Adding a Source

Add your master API key:

```bash
cred source add resend --token "$RESEND_API_KEY"
```

Or interactively (will prompt for token):

```bash
cred source add resend
```

The master token is stored securely in your OS credential store (keyring), not in plaintext files.

## Generating Credentials

Generate a new API key from the source:

```bash
cred source generate resend RESEND_EMAIL_KEY --permission sending_access -d "Email service key"
```

This creates a new API key via Resend's API and stores it in your vault with `source: resend` metadata.

## Managing Source Keys

**List API keys at the source:**

```bash
cred source keys resend
```

**Delete a generated key** (removes from source AND local vault):

```bash
cred source delete resend RESEND_EMAIL_KEY --yes
```

**List configured sources:**

```bash
cred source list
```

## Revoking a Source

Revoke source authentication (deletes all generated keys and removes master key):

```bash
cred source revoke resend --yes
```

This will:

1. Delete all API keys generated from this source at Resend
2. Remove them from the local vault
3. Remove the stored master key

---

## Resend

[Resend](https://resend.com) is an email API service. cred can generate API keys with specific permission levels.

### Permission Levels

| Permission       | Description                                           |
| ---------------- | ----------------------------------------------------- |
| `full_access`    | Can create, delete, get, and update any resource      |
| `sending_access` | Can only send emails (recommended for most use cases) |

### Example

```bash
# Add your master key (needs full_access to create other keys)
cred source add resend

# Generate a restricted key for your app
cred source generate resend EMAIL_API_KEY --permission sending_access

# Push to GitHub Actions
cred push github
```

---

## Why Sources Use Master Keys

Sources authenticate with a master API key that has permission to create additional keys. The generated keys can have narrower scopes (e.g., `sending_access` only), following the **principle of least privilege**.

Your application never sees the master key — it only gets the restricted key you generated.

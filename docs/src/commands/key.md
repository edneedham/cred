# key

Manage the encryption key and key derivation mode for your vault.

## Overview

cred supports two key modes:

| Mode         | Best For            | Key Storage                    |
| ------------ | ------------------- | ------------------------------ |
| `keyring`    | Solo developers     | OS credential store (default)  |
| `passphrase` | Team collaboration  | Derived from shared passphrase |

---

## status

Show the current key mode:

```bash
cred key status
```

Output (keyring mode):

```
Key mode: keyring
Key stored in: System Credential Store
```

Output (passphrase mode):

```
Key mode: passphrase
Salt: configured (team-shareable)
```

---

## convert

Convert between key modes.

### To Passphrase Mode

Convert a keyring-based project to passphrase mode for team sharing:

```bash
cred key convert --to passphrase --yes
```

You'll be prompted to enter and confirm a passphrase (minimum 8 characters).

After conversion:
- Share the passphrase out-of-band with your team
- The `salt` in `project.toml` is safe to commit
- Each team member derives the same key locally

### To Keyring Mode

Convert back to keyring mode (single-machine):

```bash
cred key convert --to keyring --yes
```

The key is moved back to the OS credential store.

---

## Passphrase Mode for Teams

When using passphrase mode:

1. **Initialize with passphrase:**
   ```bash
   cred init --passphrase
   ```

2. **Share the passphrase securely** (password manager, secure channel)

3. **Team members clone and use:**
   ```bash
   git clone <repo>
   cd <project>
   # cred prompts for passphrase on first use
   cred secret list
   ```

### CI/CD Integration

Set the `CRED_PASSPHRASE` environment variable to avoid interactive prompts:

```yaml
# GitHub Actions example
env:
  CRED_PASSPHRASE: ${{ secrets.CRED_PASSPHRASE }}

steps:
  - run: cred secret list
```

---

## Security Notes

- Passphrase mode uses **Argon2id** with OWASP-recommended parameters
- The salt is randomly generated and stored in `project.toml`
- The salt is **not secret** — only the passphrase must be protected
- Use a strong passphrase (12+ characters recommended)

See [Security Model](../security.md) for more details.


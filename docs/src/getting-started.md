# Getting Started

Get from zero to your first secret push in under 5 minutes.

## 1. Initialize your project

```bash
cred init
```

This creates `.cred/vault.enc` in your project.

## 2. Add a target

```bash
cred target set github
```

You'll be prompted for a fine-grained PAT with **Actions secrets** permission.

## 3. Store a secret

```bash
cred secret set DATABASE_URL "postgres://user:pass@localhost/db"
```

## 4. Push to GitHub

Preview first:

```bash
cred push github --dry-run
```

Then push:
```bash
cred push github
```

Done! Your secret is now in GitHub Actions.

---

**Next steps:**
- [Commands Reference](./commands/README.md) — all available commands
- [Sources](./concepts/sources.md) — generate credentials from APIs like Resend
- [CI/CD Integration](./ci-cd.md) — automation patterns
# status

Show a hub-and-spoke overview of your project:

```bash
cred status
```

Output:

```
Vault: 3 secrets

  RESEND_API_KEY       [resend]
  DATABASE_URL         [manual]
  JWT_SECRET           [manual] [modified]

Sources: resend ✓
Targets: github ✓
Git: edneedham/cred
```

This shows:

-   Number of secrets in vault
-   Each secret's source (manual or generated)
-   Modified secrets (changed since last push)
-   Configured sources and targets
-   Git repository (if detected)

## JSON Output

For machine-readable output:

```bash
cred status --json
```

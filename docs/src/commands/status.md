# status

Show a hub-and-spoke overview of your project:

```bash
cred status
```

Output:

```
Vault: 5 secrets (2 environments)

Environment: default
  RESEND_API_KEY       [resend]
  DATABASE_URL         [manual]

Environment: prod
  DATABASE_URL         [manual]
  JWT_SECRET           [manual]
  API_KEY              [manual]

Sources: resend ✓
Targets: github ✓
Git: edneedham/cred
```

This shows:

-   Total secrets and environment count
-   Secrets grouped by environment
-   Each secret's source (manual or generated)
-   Configured sources and targets
-   Git repository (if detected)

## JSON Output

For machine-readable output:

```bash
cred status --json
```

# Concepts

cred is built around three core concepts that work together to manage your secrets.

## Vault

The **vault** is your local encrypted secrets store. Each project has its own vault at `.cred/vault.enc` containing all your secrets with metadata like format, timestamps, and descriptions.

[Learn more about the Vault →](./vault.md)

## Sources

**Sources** are platforms that can programmatically generate credentials. Instead of manually creating API keys, you can have cred generate them for you with the appropriate permissions.

Currently supported:

-   **Resend** — Email API key generation

[Learn more about Sources →](./sources.md)

## Targets

**Targets** are platforms where you push secrets for deployment. cred uploads your vault secrets to these platforms so your workflows can access them directly.

Currently supported:

-   **GitHub** — Actions secrets

[Learn more about Targets →](./targets.md)

---

## How They Work Together

```
┌─────────────┐     generate      ┌─────────────┐      push       ┌─────────────┐
│   Source    │ ───────────────►  │    Vault    │ ──────────────► │   Target    │
│  (Resend)   │                   │ (encrypted) │                 │  (GitHub)   │
└─────────────┘                   └─────────────┘                 └─────────────┘
                                        ▲
                                        │ manual set
                                        │
                                  ┌─────────────┐
                                  │     You     │
                                  └─────────────┘
```

1. **Sources** generate credentials and store them in your vault
2. **You** can also manually add secrets to the vault
3. **Targets** receive secrets when you push from the vault

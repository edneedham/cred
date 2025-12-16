# init

Initialize a cred project.

## cred init

Initialize a new cred project in the current directory:

```bash
cred init
```

This creates:

```
.cred/
├── project.toml    # Project configuration
└── vault.enc       # Encrypted secrets vault
```

Run this once per project, typically at the repository root.



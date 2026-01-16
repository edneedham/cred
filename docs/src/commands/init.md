# init

Initialize a cred project.

## Usage

Initialize a new cred project in the current directory:

```bash
cred init
```

This creates:

```
.cred/
├── project.toml    # Project configuration (includes target bindings)
└── vault.enc       # Encrypted secrets vault
```

Run this once per project, typically at the repository root.

## What Happens

1. Creates the `.cred/` directory
2. Generates a random 32-byte encryption key
3. Stores the key in your OS credential store (Keychain, GNOME Keyring, etc.)
4. Creates an empty encrypted vault
5. Adds `.cred/` to `.gitignore`
6. **Auto-detects target bindings** from your project

## Auto-Detection

cred automatically detects and saves target bindings during init:

| Target | Detection Source                             |
| ------ | -------------------------------------------- |
| GitHub | Git remote (`git@github.com:owner/repo.git`) |
| Fly.io | `fly.toml` (`app = "my-app"`)                |
| Vercel | `.vercel/project.json` (`projectId`)         |

Example output:

```
Initialized new cred project at .cred/
🔑 Encryption key generated and stored in the System Credential Store
📍 Detected targets:
   github: owner/repo
   fly: my-app

   Run 'cred target set <target>' to authenticate each target.
```

These bindings are saved in `.cred/project.toml`:

```toml
name = "my-project"
version = "0.1.0"
id = "..."
git_repo = "owner/repo"

[targets]
github = "owner/repo"
fly = "my-app"
```

## Project Name

The project name defaults to the **directory name** where you run `cred init`.

## Next Steps

After init, authenticate your targets:

```bash
cred target set github    # Prompts for fine-grained PAT
cred target set fly       # Prompts for Fly.io token
```

Then you can push without specifying `--repo` or `--app`:

```bash
cred push github    # Uses saved binding
cred push fly       # Uses saved binding
```

## Important Notes

-   cred is **single-machine only** — the vault and encryption key stay on your dev machine
-   Use `cred push` to deploy secrets to platforms like GitHub Actions
-   Your CI/CD reads secrets from the target platform directly, not from cred
-   Target tokens are stored **per-project** to support fine-grained tokens

See [Security Model](../security.md) for more details.

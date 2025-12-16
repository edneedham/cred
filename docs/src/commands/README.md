# Commands

Complete reference for all cred commands.

## Project Management

| Command                           | Description                               |
| --------------------------------- | ----------------------------------------- |
| [`cred init`](./init.md)          | Initialize a new cred project             |
| [`cred status`](./status.md)      | Show vault, sources, and targets overview |
| [`cred doctor`](./doctor.md)      | Check project health                      |

## Secrets

| Command                                        | Description                   |
| ---------------------------------------------- | ----------------------------- |
| [`cred secret set`](./secret.md#set)           | Add or update a secret        |
| [`cred secret get`](./secret.md#get)           | Retrieve a secret value       |
| [`cred secret list`](./secret.md#list)         | List all secrets              |
| [`cred secret remove`](./secret.md#remove)     | Delete a secret from vault    |
| [`cred secret describe`](./secret.md#describe) | Update a secret's description |
| [`cred import`](./secret.md#import)            | Import from .env file         |
| [`cred export`](./secret.md#export)            | Export to .env file           |

## Deployment

| Command                    | Description                  |
| -------------------------- | ---------------------------- |
| [`cred push`](./push.md)   | Push secrets to a target     |
| [`cred prune`](./prune.md) | Delete secrets from a target |

## Sources

| Command                | Description                    |
| ---------------------- | ------------------------------ |
| `cred source add`      | Add a credential source        |
| `cred source generate` | Generate a new credential      |
| `cred source keys`     | List keys at the source        |
| `cred source delete`   | Delete a generated key         |
| `cred source list`     | List configured sources        |
| `cred source revoke`   | Remove source and all its keys |

## Targets

| Command              | Description                   |
| -------------------- | ----------------------------- |
| `cred target set`    | Configure a deployment target |
| `cred target list`   | List configured targets       |
| `cred target revoke` | Remove a target               |

## Configuration

| Command                                  | Description            |
| ---------------------------------------- | ---------------------- |
| [`cred config list`](./config.md)        | View all configuration |
| [`cred config get`](./config.md#get)     | Get a config value     |
| [`cred config set`](./config.md#set)     | Set a config value     |
| [`cred config unset`](./config.md#unset) | Remove a config value  |

---

## Global Flags

All commands support these flags:

| Flag                | Description                           |
| ------------------- | ------------------------------------- |
| `--json`            | Machine-readable JSON output          |
| `--non-interactive` | Fail instead of prompting for input   |
| `--dry-run`         | Preview changes without applying them |
| `--help`            | Show help for any command             |

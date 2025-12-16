# config

Manage global cred configuration.

Configuration is stored at `~/.config/cred/global.toml`. Sensitive values (tokens) are stored in your OS keyring, not in this file.

## list

View all configuration:

```bash
cred config list
```

---

## get

Get a specific value:

```bash
cred config get preferences.default_target
```

---

## set

Set a configuration value:

```bash
cred config set preferences.default_target github
```

---

## unset

Remove a configuration value:

```bash
cred config unset preferences.default_target
```

---

## Available Settings

| Key                          | Description                            |
| ---------------------------- | -------------------------------------- |
| `preferences.default_target` | Default target for push/prune commands |

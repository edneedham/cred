# doctor

Check project health and diagnose issues in machine readable JSON:

```bash
cred doctor
```

Output:

```json
{
  "api_version": "1",
  "data": {
    "cred_installed": true,
    "global_config": true,
    "keychain_access": true,
    "project_detected": false,
    "ready_for_push": false,
    "targets": [],
    "vault_accessible": false,
    "version": "0.4.0"
  },
  "status": "ok"
}
```

This verifies:

-   Vault file exists and is readable
-   Configuration is valid
-   Keyring access works
-   Sources and targets are reachable
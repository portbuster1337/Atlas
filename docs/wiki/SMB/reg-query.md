# reg-query

Queries (and optionally sets/deletes) registry values (PATH=..., KEY=..., VALUE=..., TYPE=..., DELETE=True)

Options: `DELETE=...`, `KEY=...`, `PATH=...`, `TYPE=...`, `VALUE=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M reg-query -o DELETE=...,KEY=...,PATH=...,TYPE=...,VALUE=...
```

Via Titanis (`SmbRegQueryModule.cs`).

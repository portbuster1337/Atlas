# change-password

Changes the current user's own password via SAMR (USER=..., OLDPASS=..., NEWPASS=...)

Options: `NEWPASS=...`, `OLDPASS=...`, `USER=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M change-password -o NEWPASS=...,OLDPASS=...,USER=...
```

Via Titanis (`SmbChangePasswordModule.cs`).

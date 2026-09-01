# localadmins

Enumerates members of the local Administrators group via SAMR

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M localadmins
```

Via Titanis `Smb2Client` (`SmbLocalAdminsModule.cs`).

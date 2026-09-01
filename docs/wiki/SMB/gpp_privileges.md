# gpp_privileges

Parses GptTmpl.inf in SYSVOL/Policies for privilege rights assignments

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M gpp_privileges
```

Via Titanis `Smb2Client` (`SmbGppPrivilegesModule.cs`).

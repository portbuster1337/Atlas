# gpp_autologin

Searches SYSVOL for Registry.xml autologon credentials (DefaultUserName/DefaultPassword)

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M gpp_autologin
```

Via Titanis `Smb2Client` (`GppAutologinModule.cs`).

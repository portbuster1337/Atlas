# gpp_password

Retrieves and decrypts GPP cpasswords from SYSVOL (Groups/Services/ScheduledTasks/DataSources/Printers/Drives)

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M gpp_password
```

Via Titanis `Smb2Client` (`GppPasswordModule.cs`).

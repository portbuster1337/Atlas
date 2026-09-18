# enum_dns

Dumps DNS zones and records via WMI (DOMAIN=<zone> to filter)

Options: `DOMAIN=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M enum_dns -o DOMAIN=...
```

Via Titanis (`SmbEnumDnsModule.cs`).

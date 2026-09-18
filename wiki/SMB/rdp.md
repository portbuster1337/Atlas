# rdp

Reads or enables/disables RDP and Restricted Admin (ACTION=enable|disable|enable-ram|disable-ram)

Options: `ACTION=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M rdp -o ACTION=...
```

Via Titanis (`SmbRdpModule.cs`).

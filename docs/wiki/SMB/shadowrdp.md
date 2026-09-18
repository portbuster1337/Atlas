# shadowrdp

Reads or enables/disables RDP shadowing (ACTION=enable|disable)

Options: `ACTION=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M shadowrdp -o ACTION=...
```

Via Titanis (`SmbShadowRdpModule.cs`).

# remote-uac

Reads or enables/disables remote UAC (ACTION=enable|disable)

Options: `ACTION=...`

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M remote-uac -o ACTION=...
```

Via Titanis (`SmbRemoteUacModule.cs`).

# wdigest

Checks WDigest UseLogonCredential (plaintext creds in LSASS)

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M wdigest
```

Via Titanis `Smb2Client` (`SmbWdigestModule.cs`).

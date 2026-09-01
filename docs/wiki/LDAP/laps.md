# laps

Retrieves LAPS passwords (ms-MCS-AdmPwd / msLAPS-Password)

```bash
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' -M laps
```

Via Titanis `LdapClient` (`LdapLapsModule.cs`).

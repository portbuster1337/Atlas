# pre2k

Finds pre-created computer accounts (UAC 4128, unauthenticated creation)

```bash
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' -M pre2k
```

Via Titanis `LdapClient` (`LdapPre2kModule.cs`).

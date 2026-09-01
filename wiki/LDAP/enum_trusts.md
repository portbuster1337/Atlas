# enum_trusts

Enumerates domain trusts (trustedDomain objects)

```bash
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' -M enum_trusts
```

Via Titanis `LdapClient` (`LdapTrustsModule.cs`).

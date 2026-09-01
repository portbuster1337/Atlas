# dump-computers

Dumps computers (FQDN, OS, OS version)

```bash
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' -M dump-computers
```

Via Titanis `LdapClient` (`LdapDumpComputersModule.cs`).

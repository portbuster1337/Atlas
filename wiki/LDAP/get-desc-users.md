# get-desc-users

Lists users with description field (may contain passwords)

```bash
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' -M get-desc-users
```

Via Titanis `LdapClient` (`LdapGetDescUsersModule.cs`).

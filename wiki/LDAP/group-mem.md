# group-mem

Retrieves members of a group (GROUP=\

```bash
atlas ldap 192.168.1.5 -u admin -p 'Password1!' -M group-mem -mo GROUP="Domain Admins"
```

Via Titanis `LdapClient` (`LdapGroupMemModule.cs`).

# modify-group

Adds/removes group members (GROUP=..., USER=..., REMOVE=True)

Options: `GROUP=...`, `REMOVE=...`, `USER=...`

```bash
atlas ldap 192.168.1.5 -u admin -p 'Password1!' -M modify-group -o GROUP=...,REMOVE=...,USER=...
```

Via Titanis (`LdapModifyGroupModule.cs`).

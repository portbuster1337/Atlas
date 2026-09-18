# add-computer

Adds/changes/deletes domain computers (NAME=..., PASSWORD=..., DELETE=True, CHANGEPW=True)

Options: `CHANGEPW=...`, `DELETE=...`, `NAME=...`, `PASSWORD=...`

```bash
atlas ldap 192.168.1.5 -u admin -p 'Password1!' -M add-computer -o CHANGEPW=...,DELETE=...,NAME=...,PASSWORD=...
```

Via Titanis (`LdapAddComputerModule.cs`).

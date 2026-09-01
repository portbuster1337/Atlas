# groupmembership

Queries groups a user belongs to (USER=username)

```bash
atlas ldap 192.168.1.5 -u admin -p 'Password1!' -M groupmembership -mo USER=Administrator
```

Via Titanis `LdapClient` (`LdapGroupMembershipModule.cs`).

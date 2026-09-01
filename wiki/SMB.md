# SMB Protocol

## Enumeration

The following assume a Kali host on 192.168.1.0/24.

### Enumerate Shares and Access
```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' --shares
atlas smb 192.168.1.5 -M shareaccess
```

### Enumerate Domain Users / Groups
```bash
atlas smb 192.168.1.5 -u admin -p pass --users
atlas smb 192.168.1.5 -u admin -p pass --groups
atlas smb 192.168.1.5 -u admin -p pass --rid-brute 4000
```

### GPP
```bash
atlas smb 192.168.1.5 -u admin -p pass -M gpp_password
atlas smb 192.168.1.5 -u admin -p pass -M gpp_autologin
```

### Generate Hosts/Krb5
```bash
atlas smb 192.168.1.5 -u admin -p pass --generate-hosts-file hosts.txt --generate-krb5-file krb5.conf
```

See also: LDAP, Kerberos, WMI, DCSync.

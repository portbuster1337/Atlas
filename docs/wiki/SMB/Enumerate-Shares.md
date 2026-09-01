# Enumerate Shares and Access

Enumerate permissions on all shares

```bash
atlas smb 192.168.1.0/24 -u user -p 'Password' --shares
```

Filter by access:

```bash
atlas smb 192.168.1.5 -u user -p 'Password' -M shareaccess
```

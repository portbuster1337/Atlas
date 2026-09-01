# Welcome

## Atlas

Atlas is a cross-platform network execution toolkit built on [TrustedSec's Titanis](https://github.com/trustedsec/Titanis) that helps automate assessing the security of *large* networks.

| Protocol | Capabilities |
|---|---|
| `smb` | Shares, users, groups, SAM/LSA, GPP, file ops, execution via WMI/SCM |
| `ldap` | Queries, BloodHound CE JSON+zip, enumeration flags |
| `kerberos` | User enum, Kerberoasting, AS-REP, Key List (RODC) |
| `wmi` | WQL queries, Win32_Process |
| `dcsync` | DRSGetNCChanges |

### Quick Start

```bash
# SMB enumeration
atlas smb 192.168.1.0/24 -u admin -p 'Password1!' --shares --users

# LDAP BloodHound
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' --bloodhound -c All

# Kerberos user enum
atlas kerberos dc01.atlas.local -d ATLAS.LOCAL -UserList users.txt
```


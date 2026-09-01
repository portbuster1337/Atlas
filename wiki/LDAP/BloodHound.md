# BloodHound Collection

Collect AD data for BloodHound CE via Titanis LDAP.

```bash
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' --bloodhound -c All
atlas ldap dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' --bloodhound -c Group,LocalAdmin,Session,Trusts
```

Output `bloodhound_<host>_<ts>/{users,groups,computers,domains,trusts,ous,gpos}.json` (`ObjectIdentifier`/`Properties`/`meta:{type,count,version:5}`) + `.zip` – import into BloodHound CE.

Supports both `-u`/`-p` (SASL) and `-bd`/`-bp` (simple bind).

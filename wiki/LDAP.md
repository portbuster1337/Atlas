# LDAP Techniques

Auth via `-u/-p` (SASL NTLM/Kerberos) or `-bd/-bp` (simple bind, `ldap server require strong auth = no`).

## Enumeration Flags
- `--users` / `--active-users` (`sAMAccountType=805306368` + `!(userAccountControl:1.2.840.113556.1.4.803:=2)`)
- `--trusted-for-delegation` (`524288`), `--password-not-required` (`32`), `--admin-count` (`adminCount=1`)
- `--get-sid` (`objectSid` → SID), `--pass-pol` (`minPwdLength`), `--dc-list` (`primaryGroupId=516`), `--gmsa`
- `--groups`/`--ous`/`--computers` (`objectClass=group/organizationalUnit/computer`), `--find-delegation`, `--asreproast` (`4194304`)

## Modules
`maq`, `pre2k` (4128), `laps`, `adcs`, `subnets` (Configuration NC), `daclread`, `certipy-find`, etc. – all `LdapFilter.Parse` + `LdapQuery` `AllPages`.

## BloodHound
- `atlas ldap <dc> -u user -p pass --bloodhound -c All` → `bloodhound_<host>_<ts>/{users,groups,computers,domains,trusts,ous,gpos}.json` (`ObjectIdentifier/Properties/meta:{type,count,version:5}`) + `.zip` – import into BloodHound CE
- `-c` alias for `--collection` supports `Group,LocalAdmin,Session,Trusts,Default,All`

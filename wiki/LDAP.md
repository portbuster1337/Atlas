# LDAP Techniques

Auth via `-u/-p` (SASL NTLM/Kerberos) or `-bd/-bp` (simple bind, `ldap server require strong auth = no`).

## Enumeration Flags
- `--users` / `--active-users` (`sAMAccountType=805306368` + `!(userAccountControl:1.2.840.113556.1.4.803:=2)`)
- `--trusted-for-delegation` (`524288`), `--password-not-required` (`32`), `--admin-count` (`adminCount=1`)
- `--get-sid` (`objectSid` → SID), `--pass-pol` (`minPwdLength`), `--dc-list` (`primaryGroupId=516`), `--gmsa`
- `--groups`/`--ous`/`--computers` (`objectClass=group/organizationalUnit/computer`), `--find-delegation`, `--asreproast` (`4194304`)

## Write Operations
```bash
atlas ldap <dc> -u admin -p pass -AddUser jdoe -AddUserPass 'Pass123!'
atlas ldap <dc> -u admin -p pass -AddComputer WS01 -AddComputerPass 'Pass123!'
atlas ldap <dc> -u admin -p pass -Modify jdoe -ModifyAttrs 'description=new desc'
atlas ldap <dc> -u admin -p pass -SetPassword jdoe -NewPassword 'Pass123!'
atlas ldap <dc> -u admin -p pass -Delete jdoe
```

## Roasting
- `--kerberoasting hashes.txt` – roast all SPN accounts (`$krb5tgs$`)
- `--asreproast asrep.txt` – real AS-REP hashes for preauth-disabled accounts (`$krb5asrep$`, Titanis `TryGetAsRepAsync`)
- `--users-export users.txt` – write enumerated users to file

## Modules
`maq`, `pre2k` (4128), `laps`, `adcs`, `subnets` (Configuration NC), `daclread`, `certipy-find`, etc. – all `LdapFilter.Parse` + `LdapQuery` `AllPages`.
New: `get-unixUserPassword`, `dns-nonsecure`, `modify-group` (`GROUP=...`, `USER=...`, `REMOVE=True`), `add-computer` (`NAME=...`, `PASSWORD=...`, `DELETE`/`CHANGEPW`).

## BloodHound
- `atlas ldap <dc> -u user -p pass --bloodhound -c All` → `bloodhound_<host>_<ts>/{users,groups,computers,domains,trusts,ous,gpos}.json` (`ObjectIdentifier/Properties/meta:{type,count,version:5}`) + `.zip` – import into BloodHound CE
- `-c` alias for `--collection` supports `Group,LocalAdmin,Session,Trusts,Default,All`

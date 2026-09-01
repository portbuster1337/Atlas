# SMB Techniques

## Enumeration
- `atlas smb <targets> -u user -p pass --shares --users --groups --disks --sessions`
- `--pass-pol` via SAMR `DomainPasswordInformation`
- `--rid-brute 4000` via `SamrLookupIdsInDomain`

## GPP
- `atlas smb <targets> -M gpp_password` – decrypts `cpassword` (AES 4e99...) from `Groups.xml`
- `gpp_autologin` – `Registry.xml` `DefaultUserName/DefaultPassword`
- `gpp_privileges` – `GptTmpl.inf` `[Privilege Rights]`

## File Hunting
- `spider` (`depth`, `maxfiles`, `match`), `keepass`/`rclone`/`winscp` etc. via `Smb2FileStream`

## Registry
- `uac` (`EnableLUA`), `wdigest` (`UseLogonCredential`), `runasppl`, `install_elevated`, `spooler` (`ScmClient`), `enum_interfaces` (`Tcpip\Parameters\Interfaces`)

## Execution
- `-x "whoami"` / `--ps "Get-Process"` via `wmiexec` (`WmiClient` `Win32_Process.Create`) or `smbexec` (`ScmClient` `Winmgmt_*` auto-delete, `__*.tmp` probe)

## Relay
- `--gen-relay-list relay.txt` (signing check), `--generate-hosts-file`/`--generate-krb5-file` (realm/KDC)

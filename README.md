# Atlas

**Atlas** is a cross-platform (Windows/Linux) network execution and security assessment toolkit built on top of [TrustedSec's Titanis](https://github.com/trustedsec/Titanis) protocol library. It is inspired by the workflow of NetExec/CrackMapExec: target lists, credential sets, modular enumeration, and compact `[HH:mm:ss] [+] host - message` console output.

> This tool is intended for **authorized security testing**. Only use against systems you have explicit permission to test.

## Features

| Protocol | Capabilities |
|---|---|
| `smb` | Auth check (NTLM/Kerberos/anonymous), shares, users, groups, disks, sessions via SRVS/SAMR; SAM/LSA via Remote Registry; file ops over SMB2/3; `--pass-pol`/`--rid-brute`/`--gen-relay-list`/`--generate-krb5-file`/`--generate-hosts-file`/`--generate-tgt`; snapshots/streams/open-files/NICs; group members, LSA SID/name lookup, registry query, services, logged-on users, task list/kill, EFS coercion; execution via `wmiexec` / `smbexec` / `mmcexec` (MMC DCOM) |
| `kerberos` | User enumeration, pre-auth/AS-REP detection, Kerberoasting, Key List attack, ticket forging (golden/silver), TGT request, password change, S4U2Self/Proxy (`-S4UserName`) |
| `wmi` | Auth via DCOM/WMI, `Win32_Process.Create` (`-x`/`-X`) or `--wmi-query` (`WQL`), namespace listing, StdRegProv registry, DCOM method invoke, EPM endpoint listing |
| `ldap` | Auth via SASL/simple bind, queries + flags (`--users`/`--trusted-for-delegation`/`--pass-pol`/`--get-sid` etc.), `--kerberoasting`, write ops (`-AddUser`/`-AddComputer`/`-Delete`/`-Modify`/`-SetPassword`), modules, `--bloodhound` (`-c`) to BloodHound CE `JSON`+`zip` |
| `dcsync` | Replicate via [MS-DRSR] (`DRSGetNCChanges`): single objects, full `--ntds` NC sync, topology (`-DcInfo`/`-ListDomains`/`-ListSites`/`-ListRoles`/`-ListPartitions`/`-ListGcs`/`-Neighbors`/`-CrackName`) |

> Flag style follows NetExec where possible (`--shares`, `--users`, `--pass-pol`, `--rid-brute`, `--local-groups`, `-d` domain, `-H` hash, `--kdcHost`, `-M`/`-o`/`-L` modules). Single-dash Titanis spellings (`-Shares`, `-ud`, `-NtlmHash`) keep working. Note: `-x`/`-X` can't coexist (case-insensitive), so PowerShell exec is `-ps`; `-d` is the domain everywhere including `kerberos` (realm falls back to it).

### Modules (74: 48 smb + 26 ldap; `atlas <proto> -L` lists them)

| Module | Protocol | Description |
|---|---|---|
| `spider` | smb | Recursive share crawler (`depth`, `maxfiles`, `match`) |
| `shareaccess` | smb | Per-share READ/WRITE access check |
| `localadmins` | smb | Local Administrators via SAMR |
| `gpp_password` | smb | Decrypts `cpassword` from `Groups.xml` etc. |
| `gpp_autologin` | smb | `Registry.xml` autologon credentials |
| `gpp_privileges` | smb | `GptTmpl.inf` privilege assignments |
| `uac` / `wdigest` / `runasppl` / `install_elevated` | smb | Registry checks via `winreg` |
| `spooler` | smb | Print Spooler status via `SCM` |
| `keepass` / `rclone` / `winscp` / `mremoteng` / `vnc` etc. | smb | File hunters on shares |
| `ntlmv1` / `reg-winlogon` / `hyperv-host` | smb | `LmCompatibilityLevel`, Winlogon autologon, Hyper-V host |
| `remote-uac` / `rdp` / `shadowrdp` | smb | Read/write remote UAC, RDP, RDP shadowing (`ACTION=...`) |
| `reg-query` | smb | Query/set/delete registry values (`PATH=...`, `KEY=...`, `VALUE=...`, `TYPE=...`, `DELETE=True`) |
| `enum_cve` | smb | Patch-level CVE check from build + UBR |
| `enum_av` | smb | AV/EDR via LSA service names + `IPC$` pipes |
| `enum_dns` / `get_netconnections` / `bitlocker` | smb | Via WMI (`root\MicrosoftDNS`, NIC configs, BitLocker) |
| `putty` / `notepad` / `recent_files` / `recyclebin` / `snipped` | smb | PuTTY sessions + `.ppk`, Notepad tab-state, Recent LNKs, recycle bin, screenshots |
| `lockscreendoors` | smb | Backdoored accessibility binaries via `FileDescription` |
| `drop-sc` / `drop-library-ms` / `scuffy` / `slinky` | smb | Coercion lure drops + `CLEANUP=True` |
| `webdav` / `smbghost` / `onelogon` / `sccm-recon6` | smb | WebClient check, SMBGhost probe, `VulnerableChannelAllowList`, SCCM recon |
| `wcc` | smb | Windows security posture checklist (UAC/LSA/RDP/Defender/LAPS/NetBIOS/...) |
| `change-password` | smb | Self-service password change via SAMR (`USER=...`, `OLDPASS=...`, `NEWPASS=...`) |
| `maq` | ldap | `ms-DS-MachineAccountQuota` |
| `pre2k` | ldap | Pre-Windows 2000 computers (`UAC 4128`) |
| `laps` | ldap | LAPS passwords |
| `adcs` | ldap | AD CS enrollment services |
| `subnets` | ldap | Sites/Subnets from Configuration NC |
| `daclread` / `badsuccessor` / `certipy-find` etc. | ldap | LDAP enumeration via Titanis |
| `get-unixUserPassword` / `dns-nonsecure` | ldap | Unix passwords, nonsecure DNS zones |
| `modify-group` / `add-computer` | ldap | Group membership, computer lifecycle (`NAME=...`, `DELETE=True`, ...) |

Shared across all protocols:

* Target specification: single host/IP, CIDR, ranges (`a.b.c.d-e`), comma lists, `@file`
* Full authentication matrix inherited from Titanis: passwords, NT hashes, AES keys, keytabs, `.kirbi`/`.ccache` tickets, PKINIT certificates, S4U, SPN overrides, SOCKS5
* Multi-host fan-out with configurable concurrency and per-host timeout
* NetExec-style console output

## Requirements

* [.NET SDK 9.0+](https://dotnet.microsoft.com/download/dotnet/9.0) (some vendored Titanis projects use C# 13)
* Network reachability to targets (445/TCP for SMB, 88/TCP for Kerberos, 389/TCP for LDAP, 135/TCP + dynamic RPC ports for WMI/DCSync)

## Build

The repository vendors the Titanis source under `external/Titanis` and builds it as part of the solution.

```bash
git clone https://github.com/<your-account>/atlas.git
cd atlas
dotnet build Atlas.sln -p:NoWarn=CS1998
```

The resulting binary is a framework-dependent .NET application:

```bash
dotnet src/Atlas.Cli/bin/Debug/net8.0/atlas.dll --help
```

## Usage

```
atlas <protocol> <targets> [authentication] [actions] [options]
```

Target specification accepts any mix of: `HOST`, `10.0.0.5`, `192.168.1.0/24`, `10.0.0.1-64`, comma-separated lists, or `@targets.txt`.

### SMB

```bash
# Credential check only
atlas smb 10.0.0.5 -u administrator -p 'Password1!'

# Enumeration
atlas smb 10.0.0.0/24 -u admin -p 'Password1!' -Shares -Users -Groups -Disks -Sessions

# SAM / LSA dumping (requires local admin)
atlas smb 10.0.0.5 -u admin -p 'Password1!' -Sam -Lsa

# File operations
atlas smb 10.0.0.5 -u admin -p pass -LsPath 'C$\Users'
atlas smb 10.0.0.5 -u admin -p pass -GetFile 'C$\Windows\win.ini'
atlas smb 10.0.0.5 -u admin -p pass -PutSource ./payload.bin -PutDest 'C$\Temp\payload.bin'

# Modules and flags
atlas smb 10.0.0.0/24 -u admin -p pass -M spider -mo 'depth=3,maxfiles=50,match=.conf'
atlas smb 10.0.0.0/24 -u admin -p pass -M shareaccess -M gpp_password
atlas smb 10.0.0.5 -u admin -p pass -M localadmins -M uac

# Flags (NetExec-like)
atlas smb 10.0.0.5 -u admin -p pass --pass-pol --rid-brute 2000
atlas smb 10.0.0.5 --Anonymous --gen-relay-list relay.txt --generate-krb5-file krb5.conf

# Password spray
atlas smb 10.0.0.0/24 -UserList users.txt -PassList 'Password1!,Summer2024!'
```

### Kerberos

```bash
# User enumeration (no credentials required)
atlas kerberos dc01.corp.local -d CORP.LOCAL -UserList users.txt

# Kerberoasting (requires any domain credential)
atlas kerberos dc01.corp.local -d CORP.LOCAL -Roast -u lowpriv -p 'Password1!'
atlas kerberos dc01.corp.local -d CORP.LOCAL -Roast -u lowpriv -p pass -SpnList 'MSSQLSvc/sql01.corp.local:1433'

# Key List attack against an RODC
atlas kerberos rodc01.corp.local -d CORP.LOCAL -rodcNo 20000 -rodcKey <aes256-hex> -UserList 'jdoe:1104'
```

### WMI

```bash
atlas wmi dc01.corp.local -d CORP.LOCAL -u admin -p pass           # auth check
atlas wmi dc01.corp.local -d CORP.LOCAL -u admin -p pass -x whoami # exec
```

### LDAP

```bash
# SASL (NTLM/Kerberos) bind - typical against Active Directory
atlas ldap dc01.corp.local -d CORP.LOCAL -u user -p pass -Query '(adminCount=1)' -Attrs sAMAccountName

# RFC 4511 simple bind - typical against OpenLDAP
atlas ldap ldap.example.com -bd 'cn=admin,dc=example,dc=com' -bp password \
    -Query '(objectClass=*)' -Base 'dc=example,dc=com'
```

### DCSync

```bash
atlas dcsync dc01.corp.local -d CORP.LOCAL -u admin -p pass krbtgt
atlas dcsync dc01.corp.local -d CORP.LOCAL -u admin -p pass jdoe '(adminCount=1)'
```

### Authentication options (all protocols)

| Option | Meaning |
|---|---|
| `-u`, `-UserName` | User name (`user`, `DOMAIN\user`, or `user@realm`) |
| `-p`, `-Password` | Password |
| `-d`, `-ud`, `-UserDomain` | Domain (NetExec `-d`; doubles as Kerberos realm fallback) |
| `-H`, `--hash`, `-NtlmHash` | NT hash (NTLM + Kerberos RC4) |
| `-AesKey` | AES128/AES256 Kerberos key |
| `-Kdc`, `--kdcHost` | KDC endpoint for Kerberos |
| `-S4UserName` | User to impersonate via S4U (Kerberos; needs `-Kdc`, companions `-Spn`/`-GenerateSt`/`-Self`) |
| `-Tgt` / `-TicketCache` / `-Tickets` | `.kirbi` / `.ccache` ticket input |
| `-Keytab` | keytab file |
| `-UserCert` (+`-UserKey`) | PKINIT certificate authentication |
| `-Anonymous` | Null session |
| `-ha` | Host address override (use FQDN in the target position + IP here for correct SPNs) |

Run `atlas <protocol> -h` for the complete parameter reference.

## Repository layout

```
Atlas.sln
Directory.Build.props      Intentional no-op (see note)
src/
  Atlas.props              Shared build settings (imported explicitly by Atlas projects)
  Atlas.Core/              Targets parsing, console output, module registry
  Atlas.Protocols.Smb/     SMB host + modules
  Atlas.Protocols.Kerberos/ AS-REQ enumeration, roasting, Key List attack
  Atlas.Protocols.Wmi/     WMI/DCOM host
  Atlas.Protocols.Ldap/    LDAP host
  Atlas.Protocols.Drsr/    DCSync
  Atlas.Cli/               Entry point / protocol dispatcher
external/Titanis/          Vendored Titanis source (built from source; not on NuGet)
```

> **Note:** `Directory.Build.props` at the repository root is intentionally empty. Titanis's build imports `$(SolutionDir)Directory.Build.props`; the file must exist when building from this solution but must stay empty so upstream settings do not leak into the vendored tree.

## License

This project links against and distributes source from TrustedSec's Titanis, which is licensed GPL-3.0. Accordingly, this project is distributed under **GPL-3.0**. See `external/Titanis/LICENSE`.

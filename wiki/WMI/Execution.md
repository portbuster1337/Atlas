# WMI Execution

Check and execute via `Win32_Process.Create`.

```bash
atlas wmi dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' -x whoami
atlas wmi dc01.atlas.local -d ATLAS.LOCAL -u admin -p 'Password1!' --wmi-query "SELECT * FROM Win32_Process"
```

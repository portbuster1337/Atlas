# Installation

Requires [.NET SDK 9.0+](https://dotnet.microsoft.com/download/dotnet/9.0).

```bash
git clone https://github.com/portbuster1337/Atlas.git
cd Atlas
dotnet build Atlas.sln -p:NoWarn=CS1998
dotnet publish src/Atlas.Cli/Atlas.Cli.csproj -r linux-x64 --self-contained -p:PublishSingleFile=true
```

Binaries: `atlas` (70M Linux ELF) / `atlas.exe` (75M Windows PE32+).

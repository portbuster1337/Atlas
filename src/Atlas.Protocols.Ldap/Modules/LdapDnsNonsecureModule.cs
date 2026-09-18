using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// NetExec dns-nonsecure: detects DNS zones allowing nonsecure updates.
/// </summary>
public sealed class LdapDnsNonsecureModule : AtlasModule<LdapClient>
{
	public override string Name => "dns-nonsecure";
	public override string Description => "Detects DNS zones allowing nonsecure dynamic updates";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		var domainRoot = ctx.Client.DomainRoot;
		if (domainRoot is null)
		{
			AtlasConsole.Warn($"{ctx.Host}:389", "(dns-nonsecure) No domain root");
			return;
		}
		string rootText = domainRoot.ToString() ?? string.Empty;
		string[] bases = new[]
		{
			$"CN=MicrosoftDNS,DC=DomainDnsZones,{rootText}",
			$"CN=MicrosoftDNS,DC=ForestDnsZones,{rootText}",
		};
		int vuln = 0, total = 0;
		foreach (var baseDn in bases)
		{
			LdapDistinguishedName searchBase;
			try { searchBase = LdapDistinguishedName.Parse(baseDn); }
			catch { continue; }
			LdapSearchResult result;
			try
			{
				var query = new LdapQuery(searchBase, LdapSearchScope.WholeSubtree, LdapFilter.Parse("(objectClass=dnsZone)"),
					new[] { new AttributeSpec("name"), new AttributeSpec("dNSProperty") }) { Options = LdapQueryOptions.AllPages };
				result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
			}
			catch { continue; }
			foreach (var entry in result.Entries)
			{
				total++;
				string name = entry["name"]?.Value?.ToString() ?? entry.EntryName?.ToString() ?? "?";
				var propAttr = entry["dNSProperty"];
				if (propAttr?.Values is null) continue;
				foreach (var v in propAttr.Values)
				{
					byte[]? blob = v as byte[];
					if (blob is null && v is string s) { try { blob = Convert.FromHexString(s); } catch { continue; } }
					if (blob is null || blob.Length < 24) continue;
					uint id = BitConverter.ToUInt32(blob, 16);
					if (id != 0x02) continue; // DSPROPERTY_ZONE_ALLOW_UPDATE
					uint dataLen = BitConverter.ToUInt32(blob, 0);
					if (blob.Length < 20 + dataLen || dataLen < 4) continue;
					uint data = BitConverter.ToUInt32(blob, 20);
					if (data == 0x01) // ZONE_UPDATE_UNSECURE
					{
						vuln++;
						AtlasConsole.Success($"{ctx.Host}:389", $"(dns-nonsecure) {name}: allows NONSECURE updates");
					}
				}
			}
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(dns-nonsecure) {vuln}/{total} zone(s) allow nonsecure updates");
	}
}

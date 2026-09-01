using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapSubnetsModule : AtlasModule<LdapClient>
{
	public override string Name => "subnets";
	public override string Description => "Retrieves Sites and Subnets from Configuration partition";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		// Get Configuration DN via rootDSE
		var rootDseQuery = new LdapQuery(null, LdapSearchScope.Base, LdapFilter.Parse("(objectClass=*)"), new[] { new AttributeSpec("configurationNamingContext") })
		{
			Options = LdapQueryOptions.None
		};
		LdapSearchResult rootDse;
		try
		{
			rootDse = await ctx.Client.Search(rootDseQuery, cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", $"(subnets) Failed to query rootDSE: {ex.Message}");
			return;
		}
		if (rootDse.EntryCount == 0)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(subnets) No rootDSE");
			return;
		}
		string configDn = rootDse.Entries[0]["configurationNamingContext"]?.Value?.ToString() ?? "";
		if (string.IsNullOrEmpty(configDn))
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(subnets) No configurationNamingContext");
			return;
		}
		var configBase = LdapDistinguishedName.Parse(configDn);
		var sitesQuery = new LdapQuery(configBase, LdapSearchScope.WholeSubtree, LdapFilter.Parse("(objectClass=site)"), new[] { new AttributeSpec("distinguishedName"), new AttributeSpec("name"), new AttributeSpec("description") })
		{
			Options = LdapQueryOptions.AllPages,
			PageSize = 100
		};
		var sitesResult = await ctx.Client.Search(sitesQuery, cancellationToken).ConfigureAwait(false);
		if (sitesResult.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(subnets) No sites found");
			return;
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(subnets) Found {sitesResult.EntryCount} site(s)");
		foreach (var site in sitesResult.Entries)
		{
			string siteDn = site["distinguishedName"]?.Value?.ToString() ?? "";
			string siteName = site["name"]?.Value?.ToString() ?? "";
			string siteDesc = site["description"]?.Value?.ToString() ?? "";
			AtlasConsole.Info($"{ctx.Host}:389", $"(subnets) Site \"{siteName}\" DN={siteDn} desc=\"{siteDesc}\"");

			// Subnets for this site: (siteObject=siteDn) under CN=Sites,CN=Configuration,...
			var sitesContainer = LdapDistinguishedName.Parse($"CN=Sites,{configDn}");
			var subnetFilter = LdapFilter.Parse($"(siteObject={EscapeFilter(siteDn)})");
			var subnetQuery = new LdapQuery(sitesContainer, LdapSearchScope.WholeSubtree, subnetFilter, new[] { new AttributeSpec("distinguishedName"), new AttributeSpec("name"), new AttributeSpec("siteObject") })
			{
				Options = LdapQueryOptions.AllPages
			};
			try
			{
				var subnetResult = await ctx.Client.Search(subnetQuery, cancellationToken).ConfigureAwait(false);
				if (subnetResult.EntryCount == 0)
				{
					AtlasConsole.Info($"{ctx.Host}:389", $"(subnets)   No subnets for site \"{siteName}\"");
				}
				else
				{
					foreach (var subnet in subnetResult.Entries)
					{
						string subnetName = subnet["name"]?.Value?.ToString() ?? "";
						AtlasConsole.Success($"{ctx.Host}:389", $"(subnets)   Subnet {subnetName} -> Site \"{siteName}\"");
					}
				}
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{ctx.Host}:389", $"(subnets) subnet search failed for {siteName}: {ex.Message}");
			}
		}
	}

	private static string EscapeFilter(string v) => v.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
}

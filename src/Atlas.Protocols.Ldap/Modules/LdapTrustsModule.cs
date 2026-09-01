using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapTrustsModule : AtlasModule<LdapClient>
{
	public override string Name => "enum_trusts";
	public override string Description => "Enumerates domain trusts (trustedDomain objects)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		var filter = LdapFilter.Parse("(objectClass=trustedDomain)");
		var attrs = new[]
		{
			new AttributeSpec("cn"),
			new AttributeSpec("trustPartner"),
			new AttributeSpec("trustDirection"),
			new AttributeSpec("trustType"),
			new AttributeSpec("trustAttributes"),
			new AttributeSpec("flatName"),
			new AttributeSpec("securityIdentifier")
		};
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs)
		{
			Options = LdapQueryOptions.AllPages
		};
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(enum_trusts) No trusts found");
			return;
		}
		foreach (var entry in result.Entries)
		{
			string cn = entry["cn"]?.Value?.ToString() ?? "";
			string partner = entry["trustPartner"]?.Value?.ToString() ?? cn;
			string direction = entry["trustDirection"]?.Value?.ToString() ?? "";
			string type = entry["trustType"]?.Value?.ToString() ?? "";
			string attrsVal = entry["trustAttributes"]?.Value?.ToString() ?? "";
			string flat = entry["flatName"]?.Value?.ToString() ?? "";
			AtlasConsole.Success($"{ctx.Host}:389", $"(enum_trusts) {partner} (cn={cn}, flat={flat}, dir={direction}, type={type}, attrs={attrsVal})");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(enum_trusts) {result.EntryCount} trust(s) enumerated");
	}
}

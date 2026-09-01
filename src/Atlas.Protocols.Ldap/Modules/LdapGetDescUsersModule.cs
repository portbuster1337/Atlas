using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGetDescUsersModule : AtlasModule<LdapClient>
{
	public override string Name => "get-desc-users";
	public override string Description => "Lists users with description field (may contain passwords)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		var filter = LdapFilter.Parse("(&(objectClass=user)(description=*))");
		var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("description") };
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs)
		{
			Options = LdapQueryOptions.AllPages,
			PageSize = 200
		};
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(get-desc-users) No users with description");
			return;
		}
		foreach (var entry in result.Entries)
		{
			string sam = entry["sAMAccountName"]?.Value?.ToString() ?? "";
			string desc = entry["description"]?.Value?.ToString() ?? "";
			AtlasConsole.Success($"{ctx.Host}:389", $"(get-desc-users) {sam}: {desc}");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(get-desc-users) {result.EntryCount} user(s) with description");
	}
}

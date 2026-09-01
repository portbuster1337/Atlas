using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGetInfoUsersModule : AtlasModule<LdapClient>
{
	public override string Name => "get-info-users";
	public override string Description => "Lists users with non-empty info field";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		var filter = LdapFilter.Parse("(&(objectClass=user)(info=*))");
		var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("info") };
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(get-info-users) No users with info field");
			return;
		}
		foreach (var e in result.Entries)
		{
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			string info = e["info"]?.Value?.ToString() ?? "";
			AtlasConsole.Success($"{ctx.Host}:389", $"(get-info-users) {sam}: {info}");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(get-info-users) {result.EntryCount} user(s)");
	}
}

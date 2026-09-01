using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// Options: TEXT (required) – search text.
/// </summary>
public sealed class LdapFindComputerModule : AtlasModule<LdapClient>
{
	public override string Name => "find-computer";
	public override string Description => "LDAP module";
	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string text = ctx.Option("TEXT", "");
		if (string.IsNullOrWhiteSpace(text))
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(find-computer) TEXT option required (e.g., TEXT=\"server\")");
			return;
		}
		string esc = Escape(text);
		string filterStr = $"(|(name=*{esc}*)(operatingSystem=*{esc}*)(dNSHostName=*{esc}*))";
		// Also ensure objectClass=computer
		filterStr = $"(&(objectClass=computer){filterStr})";
		var filter = LdapFilter.Parse(filterStr);
		var attrs = new[] { new AttributeSpec("dNSHostName"), new AttributeSpec("operatingSystem"), new AttributeSpec("sAMAccountName") };
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", $"(find-computer) No computers matching \"{text}\"");
			return;
		}
		foreach (var e in result.Entries)
		{
			string dns = e["dNSHostName"]?.Value?.ToString() ?? "";
			string os = e["operatingSystem"]?.Value?.ToString() ?? "";
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			AtlasConsole.Success($"{ctx.Host}:389", $"(find-computer) {sam} dns={dns} os={os}");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(find-computer) {result.EntryCount} match(es)");
	}

	private static string Escape(string v) => v.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
}

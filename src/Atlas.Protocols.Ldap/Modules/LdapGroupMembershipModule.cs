using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGroupMembershipModule : AtlasModule<LdapClient>
{
	public override string Name => "groupmembership";
	public override string Description => "Queries groups a user belongs to (USER=username)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string user = ctx.Option("USER", "");
		if (string.IsNullOrWhiteSpace(user))
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(groupmembership) USER option required");
			return;
		}
		string esc = Escape(user);
		var filter = LdapFilter.Parse($"(sAMAccountName={esc})");
		var attrs = new[] { new AttributeSpec("memberOf"), new AttributeSpec("distinguishedName"), new AttributeSpec("sAMAccountName") };
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages };
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", $"(groupmembership) User \"{user}\" not found");
			return;
		}
		foreach (var e in result.Entries)
		{
			string dn = e.EntryName?.ToString() ?? "";
			string sam = e["sAMAccountName"]?.Value?.ToString() ?? "";
			var memberOfVal = e["memberOf"]?.Value;
			List<string> groups = new();
			if (memberOfVal is string s)
				groups.Add(s);
			else if (memberOfVal is System.Collections.IEnumerable en && memberOfVal is not string)
				foreach (var o in en) groups.Add(o?.ToString() ?? "");
			else if (memberOfVal != null)
				groups.Add(memberOfVal.ToString() ?? "");

			if (groups.Count == 0)
				AtlasConsole.Info($"{ctx.Host}:389", $"(groupmembership) {sam} ({dn}) has no memberOf");
			else
			{
				AtlasConsole.Success($"{ctx.Host}:389", $"(groupmembership) {sam} memberOf {groups.Count} group(s):");
				foreach (var g in groups)
					AtlasConsole.Info($"{ctx.Host}:389", $"  - {g}");
			}
		}
	}

	private static string Escape(string v) => v.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
}

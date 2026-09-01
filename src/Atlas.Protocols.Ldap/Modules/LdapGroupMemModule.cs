using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGroupMemModule : AtlasModule<LdapClient>
{
	public override string Name => "group-mem";
	public override string Description => "Retrieves members of a group (GROUP=\"Domain Admins\")";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string group = ctx.Option("GROUP", "");
		if (string.IsNullOrWhiteSpace(group))
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(group-mem) GROUP option required");
			return;
		}
		string esc = Escape(group);
		// Try cn and sAMAccountName
		var filter = LdapFilter.Parse($"(|(cn={esc})(sAMAccountName={esc}))");
		var attrs = new[] { new AttributeSpec("member"), new AttributeSpec("distinguishedName"), new AttributeSpec("cn") };
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages };
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", $"(group-mem) Group \"{group}\" not found");
			return;
		}
		foreach (var e in result.Entries)
		{
			string dn = e.EntryName?.ToString() ?? "";
			string cn = e["cn"]?.Value?.ToString() ?? group;
			var memberVal = e["member"]?.Value;
			List<string> members = new();
			if (memberVal is System.Collections.IEnumerable en && memberVal is not string)
				foreach (var o in en) members.Add(o?.ToString() ?? "");
			else if (memberVal is string s)
				members.Add(s);
			else if (memberVal != null)
				members.Add(memberVal.ToString() ?? "");

			AtlasConsole.Success($"{ctx.Host}:389", $"(group-mem) Group {cn} ({dn}) has {members.Count} member(s)");
			foreach (var m in members)
				AtlasConsole.Info($"{ctx.Host}:389", $"  - {m}");
		}
	}

	private static string Escape(string v) => v.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
}

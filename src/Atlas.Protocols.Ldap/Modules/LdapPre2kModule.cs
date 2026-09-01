using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// Option: ALL=true to list all computers.
/// </summary>
public sealed class LdapPre2kModule : AtlasModule<LdapClient>
{
	public override string Name => "pre2k";
	public override string Description => "Finds pre-created computer accounts (UAC 4128, unauthenticated creation)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		bool all = ctx.Option("ALL", "false").Equals("true", StringComparison.OrdinalIgnoreCase) || ctx.Option("ALL", "0") == "1";
		string filterStr = all ? "(objectClass=computer)" : "(&(objectClass=computer)(userAccountControl=4128))";
		var filter = LdapFilter.Parse(filterStr);
		var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("userAccountControl"), new AttributeSpec("dNSHostName") };
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs)
		{
			Options = LdapQueryOptions.AllPages,
			PageSize = 100
		};
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(pre2k) No pre-created computer accounts found");
			return;
		}
		int pre2kCount = 0, total = 0;
		foreach (var entry in result.Entries)
		{
			total++;
			string sam = entry["sAMAccountName"]?.Value?.ToString() ?? "";
			string uac = entry["userAccountControl"]?.Value?.ToString() ?? "";
			string dns = entry["dNSHostName"]?.Value?.ToString() ?? "";
			bool isPre2k = uac == "4128";
			if (isPre2k) pre2kCount++;
			string marker = isPre2k ? "PRE2K" : "normal";
			AtlasConsole.Info($"{ctx.Host}:389", $"(pre2k) {sam} UAC={uac} dns={dns} [{marker}]");
			if (isPre2k)
				AtlasConsole.Success($"{ctx.Host}:389", $"(pre2k) Pre-created: {sam}");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(pre2k) Found {pre2kCount} pre-created / {total} total computer(s)");
	}
}

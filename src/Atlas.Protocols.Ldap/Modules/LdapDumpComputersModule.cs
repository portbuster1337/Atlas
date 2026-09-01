using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapDumpComputersModule : AtlasModule<LdapClient>
{
	public override string Name => "dump-computers";
	public override string Description => "Dumps computers (FQDN, OS, OS version)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string type = ctx.Option("TYPE", "fqdn").ToLowerInvariant(); // fqdn or netbios supported but we default to fqdn
		var filter = LdapFilter.Parse("(objectClass=computer)");
		var attrs = new[]
		{
			new AttributeSpec("dNSHostName"),
			new AttributeSpec("operatingSystem"),
			new AttributeSpec("operatingSystemVersion"),
			new AttributeSpec("sAMAccountName")
		};
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs)
		{
			Options = LdapQueryOptions.AllPages,
			PageSize = 200
		};
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(dump-computers) No computers found");
			return;
		}
		foreach (var entry in result.Entries)
		{
			string dns = entry["dNSHostName"]?.Value?.ToString() ?? "";
			string os = entry["operatingSystem"]?.Value?.ToString() ?? "";
			string ver = entry["operatingSystemVersion"]?.Value?.ToString() ?? "";
			string sam = entry["sAMAccountName"]?.Value?.ToString() ?? "";
			string display = type == "netbios" ? sam.TrimEnd('$') : (string.IsNullOrEmpty(dns) ? sam : dns);
			AtlasConsole.Success($"{ctx.Host}:389", $"(dump-computers) {display} - {os} {ver}".Trim());
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(dump-computers) {result.EntryCount} computer(s) dumped");
	}
}

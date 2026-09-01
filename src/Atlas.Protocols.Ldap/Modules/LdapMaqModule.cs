using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapMaqModule : AtlasModule<LdapClient>
{
	public override string Name => "maq";
	public override string Description => "Retrieves MachineAccountQuota (ms-DS-MachineAccountQuota)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		var domainRoot = ctx.Client.DomainRoot;
		if (domainRoot is null)
		{
			AtlasConsole.Warn($"{ctx.Host}:389", "(maq) No domain root");
			return;
		}

		var filter = LdapFilter.Parse("(ms-DS-MachineAccountQuota=*)");
		var query = new LdapQuery(domainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("ms-DS-MachineAccountQuota") })
		{
			Options = LdapQueryOptions.AllPages
		};
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(maq) No MachineAccountQuota found");
			return;
		}
		foreach (var entry in result.Entries)
		{
			var val = entry["ms-DS-MachineAccountQuota"]?.Value;
			string quota = FormatVal(val);
			AtlasConsole.Success($"{ctx.Host}:389", $"(maq) MachineAccountQuota: {quota} (DN: {entry.EntryName})");
		}
	}

	private static string FormatVal(object? v) => v switch
	{
		null => "",
		byte[] b => Convert.ToHexString(b),
		System.Collections.IEnumerable e when v is not string => string.Join(", ", e.Cast<object>().Select(o => o?.ToString() ?? "")),
		_ => v.ToString() ?? ""
	};
}

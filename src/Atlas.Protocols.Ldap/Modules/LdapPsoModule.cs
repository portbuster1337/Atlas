using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapPsoModule : AtlasModule<LdapClient>
{
	public override string Name => "pso";
	public override string Description => "Enumerates Password Settings Objects (FGPP)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		// PSOs are under CN=Password Settings Container,CN=System
		// Try to find via LDAP: objectClass=msDS-PasswordSettings
		var filter = LdapFilter.Parse("(objectClass=msDS-PasswordSettings)");
		var attrs = new[]
		{
			new AttributeSpec("cn"),
			new AttributeSpec("msDS-PasswordSettingsPrecedence"),
			new AttributeSpec("msDS-MinimumPasswordLength"),
			new AttributeSpec("msDS-PasswordComplexityEnabled"),
			new AttributeSpec("msDS-PSOAppliesTo")
		};
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages };
		LdapSearchResult result;
		try
		{
			result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", $"(pso) Search failed: {ex.Message}");
			return;
		}
		if (result.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(pso) No PSOs found (FGPP not configured)");
			return;
		}
		foreach (var e in result.Entries)
		{
			string cn = e["cn"]?.Value?.ToString() ?? "";
			string prec = e["msDS-PasswordSettingsPrecedence"]?.Value?.ToString() ?? "";
			string minLen = e["msDS-MinimumPasswordLength"]?.Value?.ToString() ?? "";
			string complex = e["msDS-PasswordComplexityEnabled"]?.Value?.ToString() ?? "";
			AtlasConsole.Success($"{ctx.Host}:389", $"(pso) {cn} precedence={prec} minLen={minLen} complexity={complex}");
			var applies = e["msDS-PSOAppliesTo"]?.Value;
			if (applies is System.Collections.IEnumerable en && applies is not string)
				foreach (var o in en)
					AtlasConsole.Info($"{ctx.Host}:389", $"  appliesTo: {o}");
			else if (applies != null)
				AtlasConsole.Info($"{ctx.Host}:389", $"  appliesTo: {applies}");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(pso) {result.EntryCount} PSO(s)");
	}
}

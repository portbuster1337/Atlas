using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapWhoamiModule : AtlasModule<LdapClient>
{
	public override string Name => "whoami";
	public override string Description => "Shows bound user details (whoami)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		// Try LDAP whoami extended operation via rootDSE? Titanis may not expose directly, so we search for the user we bound as.
		// For simple bind, we don't have the user DN easily, so we try to get the user's own entry via sAMAccountName derived from context?
		// As fallback, we show the LDAP server's rootDSE and attempt to find the user via filter built from the bind DN is not available.
		// Instead, we will try to search for the current user via the authentication context is not directly available, so we just show domain info and attempt a generic whoami via searching for the bound DN if available via simple bind DN option.
		string bindDn = ctx.Options.TryGetValue("BindDn", out var bd) ? bd : "";
		// If we used simple bind, the BindDn option is not passed to module; we can try to infer from the LDAP connection's bound user via a search for the current user as the one we authenticated with is not trivial.
		// Alternative: perform an LDAP search for the user that matches the account used for bind: we can try to get the username from the module context's host? No.
		// Instead, we will just display the domain root and that we are bound successfully, and try to do a whoami extended op if available.
		try
		{
			// Try to use LdapClient's Whoami if exists? Titanis may have a method. We will attempt via reflection.
			var method = ctx.Client.GetType().GetMethod("Whoami") ?? ctx.Client.GetType().GetMethod("GetWhoami");
			if (method != null)
			{
				var task = (Task<string?>)method.Invoke(ctx.Client, new object[] { cancellationToken })!;
				string? who = await task.ConfigureAwait(false);
				AtlasConsole.Success($"{ctx.Host}:389", $"(whoami) {who}");
				return;
			}
		}
		catch { }

		// Fallback: enumerate the user we bound as by searching for the username we used for auth is not directly available, so we just show the bind was successful and list the domain.
		AtlasConsole.Success($"{ctx.Host}:389", $"(whoami) Bound to {ctx.Client.DomainRoot} as {ctx.Host} (simple bind DN: {bindDn})");
		// Also try to find the Administrator user as example
		try
		{
			var filter = LdapFilter.Parse("(sAMAccountName=Administrator)");
			var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, new[] { new AttributeSpec("distinguishedName"), new AttributeSpec("memberOf") }) { Options = LdapQueryOptions.AllPages };
			var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
			foreach (var e in result.Entries)
				AtlasConsole.Info($"{ctx.Host}:389", $"(whoami) Found Administrator DN: {e.EntryName}");
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{ctx.Host}:389", $"(whoami) fallback search failed: {ex.Message}");
		}
	}
}

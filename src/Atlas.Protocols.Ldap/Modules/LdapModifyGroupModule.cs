using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// NetExec modify-group: add/remove group members via LDAP.
/// Options: GROUP=<group> (required), USER=<user> (required), REMOVE=True to remove.
/// </summary>
public sealed class LdapModifyGroupModule : AtlasModule<LdapClient>
{
	public override string Name => "modify-group";
	public override string Description => "Adds/removes group members (GROUP=..., USER=..., REMOVE=True)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string group = ctx.Option("GROUP", "");
		string user = ctx.Option("USER", "");
		bool remove = ctx.Option("REMOVE", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		if (string.IsNullOrWhiteSpace(group) || string.IsNullOrWhiteSpace(user))
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(modify-group) GROUP and USER are required (e.g. -mo GROUP='Domain Admins',USER=jdoe[,REMOVE=True])");
			return;
		}
		try
		{
			var groupDn = await ResolveDnAsync(ctx, group, cancellationToken).ConfigureAwait(false);
			var userDn = await ResolveDnAsync(ctx, user, cancellationToken).ConfigureAwait(false);
			var req = new LdapModifyRequest(groupDn);
			if (remove)
				req.DeleteValue("member", userDn.ToString());
			else
				req.AddValue("member", userDn.ToString());
			await ctx.Client.Modify(req, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:389", $"(modify-group) {(remove ? "removed" : "added")} {userDn} {(remove ? "from" : "to")} {groupDn}");
		}
		catch (Exception ex) when (!remove && ex.Message.Contains("ENTRY_EXISTS", StringComparison.OrdinalIgnoreCase))
		{
			AtlasConsole.Success($"{ctx.Host}:389", $"(modify-group) {user} is already a member of {group}");
		}
		catch (Exception ex) when (remove && ex.Message.Contains("WILL_NOT_PERFORM", StringComparison.OrdinalIgnoreCase))
		{
			AtlasConsole.Info($"{ctx.Host}:389", $"(modify-group) {user} is not a removable member of {group} (primary group membership cannot be removed via member)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", $"(modify-group) Failed: {ex.Message}");
		}
	}

	private static async Task<LdapDistinguishedName> ResolveDnAsync(AtlasModuleContext<LdapClient> ctx, string spec, CancellationToken ct)
	{
		if (spec.Contains('='))
			return LdapDistinguishedName.Parse(spec);
		var filter = LdapFilter.Parse($"(sAMAccountName={Escape(spec)})");
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, null) { Options = LdapQueryOptions.AllPages };
		var result = await ctx.Client.Search(query, ct).ConfigureAwait(false);
		if (result.EntryCount == 0)
			throw new InvalidOperationException($"Object not found: {spec}");
		return result.Entries[0].EntryName;
	}

	private static string Escape(string v) => v.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29");
}

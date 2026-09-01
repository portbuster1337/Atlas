using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapEntraIdModule : AtlasModule<LdapClient>
{
    public override string Name => "entra-id";
    public override string Description => "Find Entra ID sync server";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(description=*computer*configured*)");
        var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("description") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(entra-id) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["sAMAccountName"]?.Value?.ToString() ?? "", e["description"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(entra-id) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(entra-id) {result.EntryCount} object(s)");
    }
}

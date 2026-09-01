using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapBadsuccessorModule : AtlasModule<LdapClient>
{
    public override string Name => "badsuccessor";
    public override string Description => "Check bad successor (DMSA)";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(objectClass=msDS-DelegatedManagedServiceAccount)");
        var attrs = new[] { new AttributeSpec("sAMAccountName") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(badsuccessor) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["sAMAccountName"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(badsuccessor) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(badsuccessor) {result.EntryCount} object(s)");
    }
}

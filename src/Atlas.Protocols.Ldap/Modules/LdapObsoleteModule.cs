using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapObsoleteModule : AtlasModule<LdapClient>
{
    public override string Name => "obsolete";
    public override string Description => "Extract obsolete OS";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(&(objectCategory=computer)(operatingSystem=*))");
        var attrs = new[] { new AttributeSpec("name"), new AttributeSpec("operatingSystem") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(obsolete) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["name"]?.Value?.ToString() ?? "", e["operatingSystem"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(obsolete) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(obsolete) {result.EntryCount} object(s)");
    }
}

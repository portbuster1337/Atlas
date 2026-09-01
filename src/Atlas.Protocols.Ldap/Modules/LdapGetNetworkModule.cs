using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGetNetworkModule : AtlasModule<LdapClient>
{
    public override string Name => "get-network";
    public override string Description => "Query DNS records with IP";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(objectClass=dnsNode)");
        var attrs = new[] { new AttributeSpec("name"), new AttributeSpec("dnsRecord") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(get-network) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["name"]?.Value?.ToString() ?? "", e["dnsRecord"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(get-network) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(get-network) {result.EntryCount} object(s)");
    }
}

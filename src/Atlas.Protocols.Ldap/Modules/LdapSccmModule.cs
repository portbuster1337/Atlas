using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapSccmModule : AtlasModule<LdapClient>
{
    public override string Name => "sccm";
    public override string Description => "Find SCCM infrastructure (mSSMSManagementPoint)";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(objectClass=mSSMSManagementPoint)");
        var attrs = new[] { new AttributeSpec("distinguishedName"), new AttributeSpec("dNSHostName") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(sccm) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["distinguishedName"]?.Value?.ToString() ?? "", e["dNSHostName"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(sccm) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(sccm) {result.EntryCount} object(s)");
    }
}

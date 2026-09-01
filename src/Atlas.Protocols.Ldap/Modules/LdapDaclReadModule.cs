using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapDaclReadModule : AtlasModule<LdapClient>
{
    public override string Name => "daclread";
    public override string Description => "Read DACL of domain object";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(objectClass=domainDNS)");
        var attrs = new[] { new AttributeSpec("nTSecurityDescriptor") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(daclread) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["nTSecurityDescriptor"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(daclread) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(daclread) {result.EntryCount} object(s)");
    }
}

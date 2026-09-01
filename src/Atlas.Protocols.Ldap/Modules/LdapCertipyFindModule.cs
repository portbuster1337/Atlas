using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapCertipyFindModule : AtlasModule<LdapClient>
{
    public override string Name => "certipy-find";
    public override string Description => "Find certificate templates (simplified certipy)";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(objectClass=pKICertificateTemplate)");
        var attrs = new[] { new AttributeSpec("cn"), new AttributeSpec("msPKI-Certificate-Name-Flag") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(certipy-find) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["cn"]?.Value?.ToString() ?? "", e["msPKI-Certificate-Name-Flag"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(certipy-find) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(certipy-find) {result.EntryCount} object(s)");
    }
}

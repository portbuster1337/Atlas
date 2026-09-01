using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGetScriptPathModule : AtlasModule<LdapClient>
{
    public override string Name => "get-scriptpath";
    public override string Description => "Get scriptPath attribute";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(scriptPath=*)");
        var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("scriptPath") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(get-scriptpath) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["sAMAccountName"]?.Value?.ToString() ?? "", e["scriptPath"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(get-scriptpath) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(get-scriptpath) {result.EntryCount} object(s)");
    }
}

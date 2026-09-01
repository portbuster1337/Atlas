using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapGetUserPasswordModule : AtlasModule<LdapClient>
{
    public override string Name => "get-userPassword";
    public override string Description => "Get userPassword attribute";

    public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
    {
        var filter = LdapFilter.Parse("(userPassword=*)");
        var attrs = new[] { new AttributeSpec("sAMAccountName"), new AttributeSpec("userPassword") };
        var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs) { Options = LdapQueryOptions.AllPages, PageSize = 200 };
        var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
        if (result.EntryCount == 0)
        {
            AtlasConsole.Info($"{ctx.Host}:389", "(get-userPassword) none");
            return;
        }
        foreach (var e in result.Entries)
        {
            string dn = e.EntryName?.ToString() ?? "";
            var vals = string.Join("; ", new[] { e["sAMAccountName"]?.Value?.ToString() ?? "", e["userPassword"]?.Value?.ToString() ?? "" }.Where(s => !string.IsNullOrEmpty(s)));
            AtlasConsole.Success($"{ctx.Host}:389", $"(get-userPassword) {dn} {vals}");
        }
        AtlasConsole.Info($"{ctx.Host}:389", $"(get-userPassword) {result.EntryCount} object(s)");
    }
}

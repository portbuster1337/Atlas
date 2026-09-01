using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// </summary>
public sealed class LdapAdcsModule : AtlasModule<LdapClient>
{
	public override string Name => "adcs";
	public override string Description => "Enumerates AD CS enrollment services and certificate templates";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		// Find configuration NC
		var rootDseQuery = new LdapQuery(null, LdapSearchScope.Base, LdapFilter.Parse("(objectClass=*)"), new[] { new AttributeSpec("configurationNamingContext") });
		var rootDse = await ctx.Client.Search(rootDseQuery, cancellationToken).ConfigureAwait(false);
		string configDn = rootDse.EntryCount > 0 ? rootDse.Entries[0]["configurationNamingContext"]?.Value?.ToString() ?? "" : "";
		if (string.IsNullOrEmpty(configDn))
			configDn = $"CN=Configuration,{ctx.Client.DomainRoot}";

		var configBase = LdapDistinguishedName.Parse(configDn);

		// Enrollment Services: objectClass=pKIEnrollmentService
		var caFilter = LdapFilter.Parse("(objectClass=pKIEnrollmentService)");
		var caAttrs = new[] { new AttributeSpec("cn"), new AttributeSpec("dNSHostName"), new AttributeSpec("cACertificateDN"), new AttributeSpec("certificateTemplates") };
		var caQuery = new LdapQuery(configBase, LdapSearchScope.WholeSubtree, caFilter, caAttrs) { Options = LdapQueryOptions.AllPages };
		var caResult = await ctx.Client.Search(caQuery, cancellationToken).ConfigureAwait(false);
		if (caResult.EntryCount == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:389", "(adcs) No enrollment services found");
		}
		else
		{
			foreach (var ca in caResult.Entries)
			{
				string cn = ca["cn"]?.Value?.ToString() ?? "";
				string dns = ca["dNSHostName"]?.Value?.ToString() ?? "";
				string templates = FormatVal(ca["certificateTemplates"]?.Value);
				AtlasConsole.Success($"{ctx.Host}:389", $"(adcs) CA: {cn} dns={dns} templates={templates}");
			}
		}

		// Templates: objectClass=pKICertificateTemplate under CN=Certificate Templates,CN=Public Key Services,...
		var tmplBase = LdapDistinguishedName.Parse($"CN=Certificate Templates,CN=Public Key Services,CN=Services,{configDn}");
		var tmplFilter = LdapFilter.Parse("(objectClass=pKICertificateTemplate)");
		var tmplAttrs = new[] { new AttributeSpec("cn"), new AttributeSpec("msPKI-Certificate-Name-Flag"), new AttributeSpec("msPKI-Enrollment-Flag"), new AttributeSpec("pKIDefaultKeySpec") };
		try
		{
			var tmplQuery = new LdapQuery(tmplBase, LdapSearchScope.WholeSubtree, tmplFilter, tmplAttrs) { Options = LdapQueryOptions.AllPages, PageSize = 100 };
			var tmplResult = await ctx.Client.Search(tmplQuery, cancellationToken).ConfigureAwait(false);
			if (tmplResult.EntryCount == 0)
				AtlasConsole.Info($"{ctx.Host}:389", "(adcs) No certificate templates found");
			else
			{
				foreach (var tmpl in tmplResult.Entries)
				{
					string cn = tmpl["cn"]?.Value?.ToString() ?? "";
					AtlasConsole.Info($"{ctx.Host}:389", $"(adcs) Template: {cn}");
				}
				AtlasConsole.Info($"{ctx.Host}:389", $"(adcs) {tmplResult.EntryCount} template(s) found");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{ctx.Host}:389", $"(adcs) Template enumeration failed: {ex.Message}");
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(adcs) Done: {caResult.EntryCount} CA(s) enumerated");
	}

	private static string FormatVal(object? v) => v switch
	{
		null => "",
		byte[] b => Convert.ToHexString(b),
		System.Collections.IEnumerable e when v is not string => string.Join(", ", e.Cast<object>().Select(o => o?.ToString() ?? "")),
		_ => v.ToString() ?? ""
	};
}

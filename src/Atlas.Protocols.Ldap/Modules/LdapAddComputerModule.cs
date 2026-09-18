using System.Text;
using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// NetExec add-computer (LDAP path): create/change-password/delete computer accounts.
/// Options: NAME=<name> (required), PASSWORD=<pass>, DELETE=True, CHANGEPW=True.
/// </summary>
public sealed class LdapAddComputerModule : AtlasModule<LdapClient>
{
	public override string Name => "add-computer";
	public override string Description => "Adds/changes/deletes domain computers (NAME=..., PASSWORD=..., DELETE=True, CHANGEPW=True)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string name = ctx.Option("NAME", "");
		if (string.IsNullOrWhiteSpace(name))
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(add-computer) NAME is required (e.g. -mo NAME=WS01,PASSWORD=Pass123!)");
			return;
		}
		if (!name.EndsWith('$')) name += "$";
		string cn = name.TrimEnd('$');
		var domainRoot = ctx.Client.DomainRoot;
		if (domainRoot is null)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(add-computer) No domain root");
			return;
		}
		string dn = $"CN={cn},CN=Computers,{domainRoot}";
		bool delete = ctx.Option("DELETE", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		bool changePw = ctx.Option("CHANGEPW", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		string password = ctx.Option("PASSWORD", "");
		try
		{
			var dnParsed = LdapDistinguishedName.Parse(dn);
			if (delete)
			{
				await ctx.Client.Delete(dnParsed, cancellationToken).ConfigureAwait(false);
				AtlasConsole.Success($"{ctx.Host}:389", $"(add-computer) deleted {dn}");
				return;
			}
			if (changePw)
			{
				if (string.IsNullOrEmpty(password))
				{
					AtlasConsole.Fail($"{ctx.Host}:389", "(add-computer) PASSWORD is required with CHANGEPW");
					return;
				}
				var mod = new LdapModifyRequest(dnParsed);
				mod.ReplaceValue("unicodePwd", Encoding.Unicode.GetBytes($"\"{password}\""));
				await ctx.Client.Modify(mod, cancellationToken).ConfigureAwait(false);
				AtlasConsole.Success($"{ctx.Host}:389", $"(add-computer) password changed for {dn}");
				return;
			}
			if (string.IsNullOrEmpty(password))
			{
				AtlasConsole.Fail($"{ctx.Host}:389", "(add-computer) PASSWORD is required to create");
				return;
			}
			string domain = domainRoot.ToString()?.Replace("DC=", "", StringComparison.OrdinalIgnoreCase).Replace(",", ".") ?? "";
			var attrs = new Dictionary<string, object>
			{
				["objectClass"] = "computer",
				["sAMAccountName"] = name,
				["userAccountControl"] = 4096,
				["dnsHostName"] = $"{cn}.{domain}",
				["servicePrincipalName"] = new object[] { $"HOST/{cn}", $"HOST/{cn}.{domain}", $"RestrictedKrbHost/{cn}", $"RestrictedKrbHost/{cn}.{domain}" },
				["unicodePwd"] = Encoding.Unicode.GetBytes($"\"{password}\""),
			};
			await ctx.Client.Add(dnParsed, attrs, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:389", $"(add-computer) created {dn} (sAMAccountName={name})");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", $"(add-computer) Failed: {ex.Message}");
		}
	}
}

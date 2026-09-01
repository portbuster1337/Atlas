using System.Text.Json;
using Titanis.Ldap;

namespace Atlas.Protocols.Ldap.Modules;

/// <summary>
/// For encrypted LAPSv2, shows that decryption requires further rights; simple retrieval is done.
/// </summary>
public sealed class LdapLapsModule : AtlasModule<LdapClient>
{
	public override string Name => "laps";
	public override string Description => "Retrieves LAPS passwords (ms-MCS-AdmPwd / msLAPS-Password)";

	public override async Task RunAsync(AtlasModuleContext<LdapClient> ctx, CancellationToken cancellationToken)
	{
		string computer = ctx.Option("COMPUTER", "*");
		if (string.IsNullOrWhiteSpace(computer))
			computer = "*";
		// Normalize wildcard
		if (!computer.Contains('*') && !computer.Contains('%'))
			computer = computer; // exact name

		string filterStr = $"(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name={computer}))";
		var filter = LdapFilter.Parse(filterStr);
		var attrs = new[]
		{
			new AttributeSpec("sAMAccountName"),
			new AttributeSpec("ms-MCS-AdmPwd"),
			new AttributeSpec("msLAPS-Password"),
			new AttributeSpec("msLAPS-EncryptedPassword")
		};
		var query = new LdapQuery(ctx.Client.DomainRoot, LdapSearchScope.WholeSubtree, filter, attrs)
		{
			Options = LdapQueryOptions.AllPages,
			PageSize = 100
		};
		var result = await ctx.Client.Search(query, cancellationToken).ConfigureAwait(false);
		if (result.EntryCount == 0)
		{
			AtlasConsole.Fail($"{ctx.Host}:389", "(laps) No LAPS entries found");
			return;
		}
		foreach (var entry in result.Entries)
		{
			string sam = entry["sAMAccountName"]?.Value?.ToString() ?? "";
			string msMcs = entry["ms-MCS-AdmPwd"]?.Value?.ToString() ?? "";
			string msLaps = entry["msLAPS-Password"]?.Value?.ToString() ?? "";
			string msEnc = entry["msLAPS-EncryptedPassword"]?.Value?.ToString() ?? "";
			// ms-MCS-AdmPwd is plaintext legacy LAPS
			if (!string.IsNullOrEmpty(msMcs))
			{
				AtlasConsole.Success($"{ctx.Host}:389", $"(laps) {sam} Legacy ms-MCS-AdmPwd: {msMcs}");
				continue;
			}
			if (!string.IsNullOrEmpty(msLaps))
			{
				// msLAPS-Password is JSON: {"n":"Administrator","t":...,"p":"password"}
				try
				{
					var doc = JsonDocument.Parse(msLaps);
					string user = doc.RootElement.TryGetProperty("n", out var n) ? n.GetString() ?? "" : "";
					string pwd = doc.RootElement.TryGetProperty("p", out var p) ? p.GetString() ?? "" : msLaps;
					AtlasConsole.Success($"{ctx.Host}:389", $"(laps) {sam} msLAPS-Password user={user} pwd={pwd}");
				}
				catch
				{
					AtlasConsole.Success($"{ctx.Host}:389", $"(laps) {sam} msLAPS-Password: {msLaps}");
				}
				continue;
			}
			if (!string.IsNullOrEmpty(msEnc))
			{
				AtlasConsole.Info($"{ctx.Host}:389", $"(laps) {sam} msLAPS-EncryptedPassword present (encrypted, requires decryption via DRSUAPI) length={msEnc.Length}");
			}
		}
		AtlasConsole.Info($"{ctx.Host}:389", $"(laps) Processed {result.EntryCount} computer(s)");
	}
}

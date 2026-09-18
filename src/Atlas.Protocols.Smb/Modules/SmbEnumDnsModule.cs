using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec enum_dns: dumps AD DNS zones/records via WMI root\MicrosoftDNS.
/// Options: DOMAIN=<zone> to limit to one zone.
/// </summary>
public sealed class SmbEnumDnsModule : AtlasModule<Smb2Client>
{
	public override string Name => "enum_dns";
	public override string Description => "Dumps DNS zones and records via WMI (DOMAIN=<zone> to filter)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string onlyZone = ctx.Option("DOMAIN", "");
		try
		{
			var zones = new List<string>();
			if (!string.IsNullOrWhiteSpace(onlyZone))
				zones.Add(onlyZone);
			else
			{
				var zoneRows = await SmbWmiHelper.QueryAsync(ctx, @"root\microsoftdns", "Select Name FROM MicrosoftDNS_Zone", cancellationToken).ConfigureAwait(false);
				foreach (var r in zoneRows)
				{
					r.TryGetValue("Name", out var n);
					string name = n?.ToString() ?? string.Empty;
					if (!string.IsNullOrWhiteSpace(name)) zones.Add(name);
				}
			}
			int total = 0;
			foreach (var zone in zones)
			{
				cancellationToken.ThrowIfCancellationRequested();
				var recs = await SmbWmiHelper.QueryAsync(ctx, @"root\microsoftdns",
					$"Select TextRepresentation FROM MicrosoftDNS_ResourceRecord WHERE DomainName = '{zone}'", cancellationToken).ConfigureAwait(false);
				var byType = new SortedDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
				foreach (var r in recs)
				{
					r.TryGetValue("TextRepresentation", out var t);
					string text = t?.ToString() ?? string.Empty;
					if (string.IsNullOrWhiteSpace(text)) continue;
					var toks = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
					string rtype = toks.Length >= 3 ? toks[2] : "?";
					if (!byType.TryGetValue(rtype, out var list)) byType[rtype] = list = new List<string>();
					list.Add(text);
					total++;
				}
				AtlasConsole.Success($"{ctx.Host}:445", $"(enum_dns) zone {zone}: {recs.Count} record(s)");
				foreach (var kv in byType)
					foreach (var line in kv.Value.Take(50))
						AtlasConsole.Info($"{ctx.Host}:445", $"(enum_dns) [{kv.Key}] {line}");
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(enum_dns) {total} record(s) in {zones.Count} zone(s)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(enum_dns) Failed: {ex.Message}");
		}
	}
}

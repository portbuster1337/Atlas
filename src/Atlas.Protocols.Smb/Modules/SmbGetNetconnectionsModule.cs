using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec get_netconnections: NIC IPs + DNS suffixes via WMI.
/// </summary>
public sealed class SmbGetNetconnectionsModule : AtlasModule<Smb2Client>
{
	public override string Name => "get_netconnections";
	public override string Description => "Lists NIC IP addresses and DNS suffixes via WMI";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			var rows = await SmbWmiHelper.QueryAsync(ctx, @"root\cimv2",
				"select DNSDomainSuffixSearchOrder, IPAddress from win32_networkadapterconfiguration", cancellationToken).ConfigureAwait(false);
			int n = 0;
			foreach (var row in rows)
			{
				row.TryGetValue("IPAddress", out var ips);
				row.TryGetValue("DNSDomainSuffixSearchOrder", out var suffixes);
				string ipText = SmbWmiHelper.Fmt(ips);
				if (string.IsNullOrWhiteSpace(ipText)) continue;
				n++;
				AtlasConsole.Success($"{ctx.Host}:445", $"(get_netconnections) IP=[{ipText}] suffixes=[{SmbWmiHelper.Fmt(suffixes)}]");
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(get_netconnections) {n} NIC(s) with IPs");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(get_netconnections) Failed: {ex.Message}");
		}
	}
}

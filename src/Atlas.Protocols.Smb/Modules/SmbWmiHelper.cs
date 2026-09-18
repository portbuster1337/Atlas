using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Msdcom;
using Titanis.Msrpc.Mswmi;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// DCOM/WMI access from SMB modules (for WMI-backed checks like DNS/bitlocker/netconnections).
/// </summary>
internal static class SmbWmiHelper
{
	public static async Task<List<Dictionary<string, object?>>> QueryAsync(
		AtlasModuleContext<Smb2Client> ctx, string ns, string wql, CancellationToken ct)
	{
		var rows = new List<Dictionary<string, object?>>();
		RpcClient rpcClient = ctx.Services.CreateRpcClient();
		rpcClient.DefaultAuthLevel = RpcAuthLevel.PacketIntegrity;
		// Server 2025+ DCOM rejects NDR64 activation; NDR32 is universally accepted.
		rpcClient.OfferNdr64 = false;
		DcomClient dcom = await DcomClient.ConnectTo(ctx.Host, rpcClient, ct).ConfigureAwait(false);
		string workstation = string.Empty;
		int orpId = Random.Shared.Next(1024, 65535) & ~0x03;
		WmiClient wmi = await WmiClient.ConnectTo(workstation, orpId, dcom, ct).ConfigureAwait(false);
		var scope = await wmi.OpenNamespace(ns, "en-US", ct).ConfigureAwait(false);
		var reader = await scope.ExecuteWqlQueryAsync(wql, 20, ct).ConfigureAwait(false);
		while (await reader.ReadAsync(ct).ConfigureAwait(false))
		{
			if (reader.Current is not WmiInstanceObject inst) continue;
			var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
			foreach (var prop in inst.Properties)
			{
				string name = prop.ClassProperty?.Name ?? "unknown";
				row[name] = prop.Value;
			}
			rows.Add(row);
			if (rows.Count >= 500) break;
		}
		return rows;
	}

	public static string Fmt(object? v) => v switch
	{
		null => string.Empty,
		byte[] b => Convert.ToHexString(b),
		System.Collections.IEnumerable e when v is not string => string.Join(", ", e.Cast<object>().Select(o => o?.ToString() ?? string.Empty)),
		_ => v.ToString() ?? string.Empty,
	};
}

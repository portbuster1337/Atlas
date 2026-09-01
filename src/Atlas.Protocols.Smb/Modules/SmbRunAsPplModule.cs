using Titanis.Msrpc;
using Titanis.DceRpc;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// </summary>
public sealed class SmbRunAsPplModule : AtlasModule<Smb2Client>
{
	public override string Name => "runasppl";
	public override string Description => "Checks LSA RunAsPPL protection (credential guard)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			using var reg = await BindWinregAsync(ctx, cancellationToken).ConfigureAwait(false);
			await using var baseKey = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			var lsaKey = await TryOpen(baseKey, @"SYSTEM\CurrentControlSet\Control\Lsa", cancellationToken).ConfigureAwait(false);
			if (lsaKey == null)
			{
				AtlasConsole.Fail($"{ctx.Host}:445", "(runasppl) LSA key not accessible");
				return;
			}
			await using (lsaKey)
			{
				var runAsPpl = await TryGetValue(lsaKey, "RunAsPPL", cancellationToken).ConfigureAwait(false);
				var runAsPplEnabled = await TryGetValue(lsaKey, "RunAsPPLEnabled", cancellationToken).ConfigureAwait(false);
				AtlasConsole.Info($"{ctx.Host}:445", $"(runasppl) RunAsPPL={Fmt(runAsPpl)} RunAsPPLEnabled={Fmt(runAsPplEnabled)}");
				if (runAsPpl == null && runAsPplEnabled == null)
					AtlasConsole.Info($"{ctx.Host}:445", "(runasppl) LSA protection not configured (default)");
				else if (runAsPpl is uint u && u != 0 || runAsPplEnabled is uint ue && ue != 0)
					AtlasConsole.Success($"{ctx.Host}:445", "(runasppl) LSA protection ENABLED");
				else
					AtlasConsole.Info($"{ctx.Host}:445", "(runasppl) LSA protection disabled or minimal");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(runasppl) Failed: {ex.Message}");
		}
	}

	private static async Task<IRegistryKey?> TryOpen(IRegistryKey baseKey, string path, CancellationToken ct)
	{
		try { return await baseKey.OpenSubkey(path, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false); }
		catch { return null; }
	}

	private static async Task<object?> TryGetValue(IRegistryKey key, string name, CancellationToken ct)
	{
		try
		{
			var v = await key.GetValue(name, ct).ConfigureAwait(false);
			if (v.TypedValue != null) return v.TypedValue;
			if (v.Bytes != null && v.Bytes.Length >= 4) return BitConverter.ToUInt32(v.Bytes, 0);
			return v.Bytes;
		}
		catch { return null; }
	}

	private static string Fmt(object? v) => v?.ToString() ?? "N/A";

	private static async Task<RemoteRegistryClient> BindWinregAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		RemoteRegistryClient client = new RemoteRegistryClient();
		string pipe = client.WellKnownPipeName ?? "winreg";
		await rpc.ConnectPipe(client, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), ct).ConfigureAwait(false);
		return client;
	}
}

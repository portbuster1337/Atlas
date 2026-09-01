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
public sealed class SmbWdigestModule : AtlasModule<Smb2Client>
{
	public override string Name => "wdigest";
	public override string Description => "Checks WDigest UseLogonCredential (plaintext creds in LSASS)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			using var reg = await BindWinregAsync(ctx, cancellationToken).ConfigureAwait(false);
			await using var baseKey = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			await using var wdigestKey = await baseKey.OpenSubkey(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			var val = await TryGetDword(wdigestKey, "UseLogonCredential", cancellationToken).ConfigureAwait(false);
			AtlasConsole.Info($"{ctx.Host}:445", $"(wdigest) UseLogonCredential={Fmt(val)}");
			if (val == 1)
				AtlasConsole.Success($"{ctx.Host}:445", "(wdigest) WDigest is ENABLED (1) – plaintext passwords may be in LSASS");
			else if (val == 0)
				AtlasConsole.Info($"{ctx.Host}:445", "(wdigest) WDigest is disabled (0)");
			else
				AtlasConsole.Info($"{ctx.Host}:445", "(wdigest) WDigest not explicitly configured (default disabled on modern Windows)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(wdigest) Failed: {ex.Message}");
		}
	}

	private static async Task<uint?> TryGetDword(IRegistryKey key, string name, CancellationToken ct)
	{
		try
		{
			var v = await key.GetValue(name, ct).ConfigureAwait(false);
			if (v.TypedValue is int i) return (uint)i;
			if (v.TypedValue is uint u) return u;
			if (v.TypedValue is long l) return (uint)l;
			if (v.Bytes != null && v.Bytes.Length >= 4) return BitConverter.ToUInt32(v.Bytes, 0);
		}
		catch { }
		return null;
	}

	private static string Fmt(uint? v) => v?.ToString() ?? "N/A (not set)";

	private static async Task<RemoteRegistryClient> BindWinregAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		RemoteRegistryClient client = new RemoteRegistryClient();
		string pipe = client.WellKnownPipeName ?? "winreg";
		await rpc.ConnectPipe(client, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), ct).ConfigureAwait(false);
		return client;
	}
}

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
public sealed class SmbUacModule : AtlasModule<Smb2Client>
{
	public override string Name => "uac";
	public override string Description => "Checks UAC status via registry (ConsentPromptBehaviorAdmin, EnableLUA)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			using var reg = await BindWinregAsync(ctx, cancellationToken).ConfigureAwait(false);
			await using var baseKey = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			await using var policyKey = await baseKey.OpenSubkey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			var consent = await TryGetDword(policyKey, "ConsentPromptBehaviorAdmin", cancellationToken).ConfigureAwait(false);
			var enableLUA = await TryGetDword(policyKey, "EnableLUA", cancellationToken).ConfigureAwait(false);
			var promptOnSecure = await TryGetDword(policyKey, "PromptOnSecureDesktop", cancellationToken).ConfigureAwait(false);

			AtlasConsole.Info($"{ctx.Host}:445", $"(uac) ConsentPromptBehaviorAdmin={Fmt(consent)} EnableLUA={Fmt(enableLUA)} PromptOnSecureDesktop={Fmt(promptOnSecure)}");
			if (enableLUA == 0)
				AtlasConsole.Success($"{ctx.Host}:445", "(uac) UAC is DISABLED (EnableLUA=0) – privilege escalation may be easier");
			else if (consent == 2)
				AtlasConsole.Info($"{ctx.Host}:445", "(uac) UAC set to prompt for consent (2)");
			else
				AtlasConsole.Info($"{ctx.Host}:445", "(uac) UAC appears enabled");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(uac) Failed: {ex.Message}");
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

	private static string Fmt(uint? v) => v?.ToString() ?? "N/A";

	private static async Task<RemoteRegistryClient> BindWinregAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		RemoteRegistryClient client = new RemoteRegistryClient();
		string pipe = client.WellKnownPipeName ?? "winreg";
		await rpc.ConnectPipe(client, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), ct).ConfigureAwait(false);
		return client;
	}
}

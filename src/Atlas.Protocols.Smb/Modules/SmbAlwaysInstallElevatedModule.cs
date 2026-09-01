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
public sealed class SmbAlwaysInstallElevatedModule : AtlasModule<Smb2Client>
{
	public override string Name => "install_elevated";
	public override string Description => "Checks AlwaysInstallElevated (MSI privilege escalation)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			using var reg = await BindWinregAsync(ctx, cancellationToken).ConfigureAwait(false);
			await using var lmBase = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);

			uint? lmVal = await TryGetDword(lmBase, @"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", cancellationToken).ConfigureAwait(false);
			AtlasConsole.Info($"{ctx.Host}:445", $"(install_elevated) HKLM\\...\\Installer AlwaysInstallElevated={Fmt(lmVal)}");

			// HKCU for current user is not typically accessible via Remote Registry; we check HKU\.DEFAULT as approximation
			uint? hkcuVal = null;
			try
			{
				await using var usersBase = await reg.OpenUsers(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
				hkcuVal = await TryGetDword(usersBase, @".DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", cancellationToken).ConfigureAwait(false);
				AtlasConsole.Info($"{ctx.Host}:445", $"(install_elevated) HKU\\.DEFAULT\\... AlwaysInstallElevated={Fmt(hkcuVal)}");
			}
			catch { AtlasConsole.Info($"{ctx.Host}:445", "(install_elevated) HKCU check via HKU\\.DEFAULT not available"); }

			if (lmVal == 1)
				AtlasConsole.Success($"{ctx.Host}:445", "(install_elevated) VULNERABLE if HKCU also 1 (both must be 1)");
			else
				AtlasConsole.Info($"{ctx.Host}:445", "(install_elevated) Not vulnerable (HKLM not 1)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(install_elevated) Failed: {ex.Message}");
		}
	}

	private static async Task<uint?> TryGetDword(IRegistryKey baseKey, string subPath, string valueName, CancellationToken ct)
	{
		try
		{
			await using var key = await baseKey.OpenSubkey(subPath, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false);
			var v = await key.GetValue(valueName, ct).ConfigureAwait(false);
			if (v.TypedValue is int i) return (uint)i;
			if (v.TypedValue is uint u) return u;
			if (v.TypedValue is long l) return (uint)l;
			if (v.Bytes != null && v.Bytes.Length >= 4) return BitConverter.ToUInt32(v.Bytes, 0);
		}
		catch { }
		return null;
	}

	private static string Fmt(uint? v) => v?.ToString() ?? "0 (not set)";

	private static async Task<RemoteRegistryClient> BindWinregAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		RemoteRegistryClient client = new RemoteRegistryClient();
		string pipe = client.WellKnownPipeName ?? "winreg";
		await rpc.ConnectPipe(client, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), ct).ConfigureAwait(false);
		return client;
	}
}

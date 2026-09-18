using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec remote-uac: enable/disable remote UAC (LocalAccountTokenFilterPolicy).
/// Options: ACTION=enable|disable (default: read current state).
/// </summary>
public sealed class SmbRemoteUacModule : AtlasModule<Smb2Client>
{
	public override string Name => "remote-uac";
	public override string Description => "Reads or enables/disables remote UAC (ACTION=enable|disable)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string action = ctx.Option("ACTION", "").Trim().ToLowerInvariant();
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyAll, cancellationToken).ConfigureAwait(false);
			await using var key = await lm.OpenSubkey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);

			if (action is not "enable" and not "disable")
			{
				uint? cur = await TryGetDword(key, "LocalAccountTokenFilterPolicy", cancellationToken).ConfigureAwait(false);
				AtlasConsole.Info($"{ctx.Host}:445", $"(remote-uac) LocalAccountTokenFilterPolicy={Fmt(cur)} (pass -mo ACTION=enable|disable to change)");
				return;
			}

			uint want = (action == "disable") ? 1u : 0u;
			try
			{
				await key.SetValue("LocalAccountTokenFilterPolicy", RegistryValueType.DwordLE, BitConverter.GetBytes(want), cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex) when (ex.Message.Contains("NOT_FOUND", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("0x00000002"))
			{
				await using var created = await lm.CreateSubkey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				await created.SetValue("LocalAccountTokenFilterPolicy", RegistryValueType.DwordLE, BitConverter.GetBytes(want), cancellationToken).ConfigureAwait(false);
			}
			AtlasConsole.Success($"{ctx.Host}:445", $"(remote-uac) Remote UAC {(action == "disable" ? "disabled" : "enabled")} (LocalAccountTokenFilterPolicy={want})");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(remote-uac) Failed: {ex.Message}");
		}
	}

	private static async Task<uint?> TryGetDword(RegistryKey key, string name, CancellationToken ct)
	{
		try
		{
			var v = await key.GetValue(name, ct).ConfigureAwait(false);
			if (v.TypedValue is int i) return (uint)i;
			if (v.TypedValue is uint u) return u;
			if (v.TypedValue is long l) return (uint)l;
			if (v.Bytes is { Length: >= 4 }) return BitConverter.ToUInt32(v.Bytes, 0);
		}
		catch { }
		return null;
	}

	private static string Fmt(uint? v) => v?.ToString() ?? "not set";
}

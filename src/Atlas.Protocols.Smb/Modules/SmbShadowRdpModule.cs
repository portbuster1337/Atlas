using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec shadowrdp: enable/disable RDP shadowing.
/// Options: ACTION=enable|disable (default: read state).
/// </summary>
public sealed class SmbShadowRdpModule : AtlasModule<Smb2Client>
{
	public override string Name => "shadowrdp";
	public override string Description => "Reads or enables/disables RDP shadowing (ACTION=enable|disable)";

	private const string KeyPath = @"Software\Policies\Microsoft\Windows NT\Terminal Services";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string action = ctx.Option("ACTION", "").Trim().ToLowerInvariant();
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyAll, cancellationToken).ConfigureAwait(false);

			async Task<uint?> GetShadow()
			{
				try
				{
					await using var k = await lm.OpenSubkey(KeyPath, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
					var v = await k.GetValue("Shadow", cancellationToken).ConfigureAwait(false);
					if (v.TypedValue is int i) return (uint)i;
					if (v.TypedValue is uint u) return u;
					if (v.Bytes is { Length: >= 4 }) return BitConverter.ToUInt32(v.Bytes, 0);
				}
				catch { }
				return null;
			}

			if (action is not "enable" and not "disable")
			{
				uint? cur = await GetShadow().ConfigureAwait(false);
				AtlasConsole.Info($"{ctx.Host}:445", $"(shadowrdp) Shadow={cur?.ToString() ?? "not set"} (pass -mo ACTION=enable|disable to change)");
				return;
			}

			uint want = (action == "enable") ? 2u : 0u;
			RegistryKey key;
			try
			{
				key = await lm.OpenSubkey(KeyPath, RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			}
			catch
			{
				key = await lm.CreateSubkey(KeyPath, RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			}
			await using (key)
			{
				await key.SetValue("Shadow", RegistryValueType.DwordLE, BitConverter.GetBytes(want), cancellationToken).ConfigureAwait(false);
			}
			AtlasConsole.Success($"{ctx.Host}:445", $"(shadowrdp) {(action == "enable" ? "Shadow RDP with full access enabled" : "Shadow RDP disabled")} (Shadow={want})");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(shadowrdp) Failed: {ex.Message}");
		}
	}
}

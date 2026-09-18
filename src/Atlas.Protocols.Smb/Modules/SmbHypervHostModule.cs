using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec hyperv-host: Hyper-V guest host name via integration services.
/// </summary>
public sealed class SmbHypervHostModule : AtlasModule<Smb2Client>
{
	public override string Name => "hyperv-host";
	public override string Description => "Reads Hyper-V host name from guest integration services";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			string hostName;
			try
			{
				await using var key = await lm.OpenSubkey(@"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				var v = await key.GetValue("HostName", cancellationToken).ConfigureAwait(false);
				hostName = v.TypedValue?.ToString() ?? string.Empty;
			}
			catch
			{
				AtlasConsole.Info($"{ctx.Host}:445", "(hyperv-host) key does not exist - not a Hyper-V guest (or no Integration Services)");
				return;
			}
			AtlasConsole.Success($"{ctx.Host}:445", $"(hyperv-host) HostName: {hostName}");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(hyperv-host) Failed: {ex.Message}");
		}
	}
}

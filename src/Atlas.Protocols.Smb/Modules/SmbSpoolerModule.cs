using Titanis.Winterop.Security;
using Titanis.Msrpc;
using Titanis.DceRpc;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Msscmr;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// </summary>
public sealed class SmbSpoolerModule : AtlasModule<Smb2Client>
{
	public override string Name => "spooler";
	public override string Description => "Checks if Print Spooler service is enabled/running";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			ScmClient scmClient = new ScmClient();
			string pipe = scmClient.WellKnownPipeName ?? "svcctl";
			await rpc.ConnectPipe(scmClient, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

			using Scm scm = await scmClient.OpenScm(ScmAccessRights.Connect | ScmAccessRights.EnumerateService, cancellationToken).ConfigureAwait(false);
			try
			{
				using Service svc = await scm.OpenServiceAsync("Spooler", ServiceAccessRights.QueryStatus, cancellationToken).ConfigureAwait(false);
				var status = await svc.QueryStatusAsync(cancellationToken).ConfigureAwait(false);
				string state = status.CurrentState.ToString();
				AtlasConsole.Info($"{ctx.Host}:445", $"(spooler) Spooler service status: {state} ({(int)status.CurrentState})");
				if (status.CurrentState == ServiceState.Running)
					AtlasConsole.Success($"{ctx.Host}:445", "(spooler) Spooler is RUNNING – may be vulnerable to PrintNightmare");
				else
					AtlasConsole.Info($"{ctx.Host}:445", "(spooler) Spooler not running");
			}
			catch (Exception ex) when (ex.Message.Contains("0x424") || ex.Message.Contains("1060"))
			{
				AtlasConsole.Info($"{ctx.Host}:445", "(spooler) Spooler service not installed / disabled");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(spooler) Failed: {ex.Message}");
		}
	}
}

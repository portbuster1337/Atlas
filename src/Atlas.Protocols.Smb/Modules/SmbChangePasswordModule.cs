using System.Net;
using Titanis;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.DceRpc.Epm;
using Titanis.Msrpc;
using Titanis.Msrpc.Mssamr;
using Titanis.Net;
using Titanis.Security;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec change-password (SAMR self-change path): changes the caller's own password.
/// Options: USER=<own account> (required), OLDPASS=<current> (required), NEWPASS=<new> (required).
/// Admin reset of OTHER accounts is not exposed by Titanis: use ldap -SetPassword.
/// </summary>
public sealed class SmbChangePasswordModule : AtlasModule<Smb2Client>
{
	public override string Name => "change-password";
	public override string Description => "Changes the current user's own password via SAMR (USER=..., OLDPASS=..., NEWPASS=...)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string newPass = ctx.Option("NEWPASS", "");
		string target = ctx.Option("USER", "");
		string oldPass = ctx.Option("OLDPASS", "");
		if (string.IsNullOrEmpty(newPass) || string.IsNullOrEmpty(target) || string.IsNullOrEmpty(oldPass))
		{
			AtlasConsole.Fail($"{ctx.Host}:445", "(change-password) USER, OLDPASS and NEWPASS are required (e.g. -mo USER=lowpriv,OLDPASS=Old!,NEWPASS=New!)");
			return;
		}
		try
		{
			try
			{
				await ChangeViaPipeAsync(ctx, target, oldPass, newPass, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex) when (IsAccessDenied(ex))
			{
				// Hardened DCs demand RPC privacy for password ops; pipes bind at None. Retry over TCP.
				AtlasConsole.Info($"{ctx.Host}:445", "(change-password) pipe denied, retrying SAMR over TCP with privacy");
				await ChangeViaTcpAsync(ctx, target, oldPass, newPass, cancellationToken).ConfigureAwait(false);
			}
			AtlasConsole.Success($"{ctx.Host}:445", $"(change-password) password changed for '{target}'");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(change-password) Failed: {ex.Message}");
		}
	}

	private static bool IsAccessDenied(Exception ex) =>
		ex.Message.Contains("ACCESS_DENIED", StringComparison.OrdinalIgnoreCase)
		|| ex.Message.Contains("0xC0000022", StringComparison.OrdinalIgnoreCase);

	private static async Task ChangeViaPipeAsync(AtlasModuleContext<Smb2Client> ctx, string target, string oldPass, string newPass, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		var samClient = new SamClient();
		await rpc.ConnectPipe(samClient, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, samClient.WellKnownPipeName ?? "samr"), ct).ConfigureAwait(false);
		await samClient.UpdateUserPassword(target, oldPass, newPass, ct).ConfigureAwait(false);
	}

	private static async Task ChangeViaTcpAsync(AtlasModuleContext<Smb2Client> ctx, string target, string oldPass, string newPass, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		rpc.DefaultAuthLevel = RpcAuthLevel.PacketPrivacy;
		var epmSpn = new ServicePrincipalName(PrincipalNameType.ServiceInstance, ServiceClassNames.Rpc, ctx.Host);
		EpmClient epm = await rpc.ConnectTcp<EpmClient>(new DnsEndPoint(ctx.Host, EpmClient.EPMapperPort), epmSpn, RpcAuthLevel.None, ct).ConfigureAwait(false);
		var remoteEP = await epm.TryMapTcp(RpcInterfaceId.GetForType(typeof(ms_samr.samr)), null, ct).ConfigureAwait(false);
		if (remoteEP is null)
			throw new InvalidOperationException("EPM has no TCP endpoint for SAMR");
		var samClient = new SamClient();
		await rpc.ConnectTcp(samClient, remoteEP, samClient.GetSpnFor(ctx.Host), RpcAuthLevel.PacketPrivacy, ct).ConfigureAwait(false);
		await samClient.UpdateUserPassword(target, oldPass, newPass, ct).ConfigureAwait(false);
	}
}

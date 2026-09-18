using Titanis;
using Titanis.Msrpc;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec ntlmv1: checks LmCompatibilityLevel (NTLMv1 allowed when &lt; 3).
/// </summary>
public sealed class SmbNtlmv1Module : AtlasModule<Smb2Client>
{
	public override string Name => "ntlmv1";
	public override string Description => "Checks if NTLMv1 is allowed (LmCompatibilityLevel < 3)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			await using var key = await lm.OpenSubkey(@"SYSTEM\CurrentControlSet\Control\Lsa", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			uint? level = null;
			try
			{
				var v = await key.GetValue("lmcompatibilitylevel", cancellationToken).ConfigureAwait(false);
				level = v.TypedValue switch
				{
					int i => (uint)i,
					uint u => u,
					long l => (uint)l,
					_ => (v.Bytes is { Length: >= 4 }) ? BitConverter.ToUInt32(v.Bytes, 0) : null,
				};
			}
			catch { }
			if (level is null)
				AtlasConsole.Info($"{ctx.Host}:445", "(ntlmv1) LmCompatibilityLevel not set (default 3 - NTLMv1 refused)");
			else if (level < 3)
				AtlasConsole.Success($"{ctx.Host}:445", $"(ntlmv1) NTLMv1 ALLOWED - LmCompatibilityLevel = {level}");
			else
				AtlasConsole.Info($"{ctx.Host}:445", $"(ntlmv1) NTLMv1 refused - LmCompatibilityLevel = {level}");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(ntlmv1) Failed: {ex.Message}");
		}
	}
}

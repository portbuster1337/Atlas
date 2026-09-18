using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec sccm-recon6: SCCM site recon via registry (RECON-6).
/// </summary>
public sealed class SmbSccmRecon6Module : AtlasModule<Smb2Client>
{
	public override string Name => "sccm-recon6";
	public override string Description => "SCCM site recon: DPs, MPs and site DB servers via registry";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);

			async Task<RegistryKey?> TryOpen(string path)
			{
				try { return await lm.OpenSubkey(path, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false); }
				catch { return null; }
			}

			await using var sms = await TryOpen(@"SOFTWARE\Microsoft\SMS").ConfigureAwait(false);
			if (sms is null)
			{
				AtlasConsole.Info($"{ctx.Host}:445", "(sccm-recon6) SOFTWARE\\Microsoft\\SMS not found - no SCCM client footprint");
				return;
			}
			AtlasConsole.Success($"{ctx.Host}:445", "(sccm-recon6) SOFTWARE\\Microsoft\\SMS present");
			await foreach (var sub in sms.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
			{
				string n = sub.KeyName;
				if (n.Equals("DP", StringComparison.OrdinalIgnoreCase))
					AtlasConsole.Success($"{ctx.Host}:445", "(sccm-recon6) Distribution Point (DP) role detected");
				else if (n.Equals("MP", StringComparison.OrdinalIgnoreCase))
					AtlasConsole.Success($"{ctx.Host}:445", "(sccm-recon6) Management Point (MP) role detected");
				else
					AtlasConsole.Info($"{ctx.Host}:445", $"(sccm-recon6) SMS subkey: {n}");
			}

			await using var dp = await TryOpen(@"SOFTWARE\Microsoft\SMS\DP").ConfigureAwait(false);
			if (dp is not null)
			{
				await foreach (var v in dp.GetValues(true, cancellationToken).ConfigureAwait(false))
				{
					if (v.Name.Equals("SiteCode", StringComparison.OrdinalIgnoreCase) ||
						v.Name.Equals("SiteServer", StringComparison.OrdinalIgnoreCase) ||
						v.Name.Equals("ManagementPoints", StringComparison.OrdinalIgnoreCase) ||
						v.Name.Equals("IsPXE", StringComparison.OrdinalIgnoreCase) ||
						v.Name.Equals("IsAnonymousAccessEnabled", StringComparison.OrdinalIgnoreCase))
						AtlasConsole.Success($"{ctx.Host}:445", $"(sccm-recon6) DP {v.Name} = {Fmt(v)}");
				}
			}

			await using var compMgr = await TryOpen(@"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers").ConfigureAwait(false);
			if (compMgr is not null)
			{
				await foreach (var sub in compMgr.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
					AtlasConsole.Success($"{ctx.Host}:445", $"(sccm-recon6) Site DB server: {sub.KeyName}");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(sccm-recon6) Failed: {ex.Message}");
		}
	}

	private static string Fmt(RegistryValueInfo v)
	{
		if (v.TypedValue is not null) return v.TypedValue.ToString() ?? string.Empty;
		if (v.Bytes is not null) return Convert.ToHexString(v.Bytes);
		return string.Empty;
	}
}

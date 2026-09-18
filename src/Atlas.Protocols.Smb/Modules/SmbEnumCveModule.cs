using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec enum_cve: patch-level CVE check from OS build + UBR.
/// </summary>
public sealed class SmbEnumCveModule : AtlasModule<Smb2Client>
{
	public override string Name => "enum_cve";
	public override string Description => "Checks patchable CVEs from Windows build + UBR (SMBGhost/NTLM/BadSuccessor/...)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			await using var cv = await lm.OpenSubkey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);

			async Task<string?> GetString(string name)
			{
				try
				{
					var v = await cv.GetValue(name, cancellationToken).ConfigureAwait(false);
					return v.TypedValue?.ToString();
				}
				catch { return null; }
			}
			async Task<uint?> GetDword(string name)
			{
				try
				{
					var v = await cv.GetValue(name, cancellationToken).ConfigureAwait(false);
					if (v.TypedValue is int i) return (uint)i;
					if (v.TypedValue is uint u) return u;
					if (v.Bytes is { Length: >= 4 }) return BitConverter.ToUInt32(v.Bytes, 0);
				}
				catch { }
				return null;
			}

			uint major = (await GetDword("CurrentMajorVersionNumber").ConfigureAwait(false)) ?? 0;
			uint minor = (await GetDword("CurrentMinorVersionNumber").ConfigureAwait(false)) ?? 0;
			uint build = 0;
			string? buildStr = await GetString("CurrentBuildNumber").ConfigureAwait(false);
			uint.TryParse(buildStr, out build);
			uint ubr = (await GetDword("UBR").ConfigureAwait(false)) ?? 0;
			string? product = await GetString("ProductName").ConfigureAwait(false);
			AtlasConsole.Info($"{ctx.Host}:445", $"(enum_cve) {product} build {major}.{minor}.{build} UBR {ubr}");

			bool isDc = await IsDcAsync(ctx, cancellationToken).ConfigureAwait(false);
			foreach (var (cve, info) in SmbEnumCveData.Cves)
			{
				if (info.DcOnly && !isDc)
				{
					AtlasConsole.Info($"{ctx.Host}:445", $"(enum_cve) Skipping {info.Alias} - only applicable to Domain Controllers");
					continue;
				}
				var match = info.Patches.FirstOrDefault(p => p.Major == (int)major && p.Minor == (int)minor && p.Build == (int)build);
				if (match == default)
				{
					AtlasConsole.Info($"{ctx.Host}:445", $"(enum_cve) {cve} ({info.Alias}): no patch data for this build");
					continue;
				}
				if ((int)ubr < match.MinUbr)
					AtlasConsole.Success($"{ctx.Host}:445", $"(enum_cve) {cve} - {info.Alias} - VULNERABLE (UBR {ubr} < {match.MinUbr}): {info.Message}");
				else
					AtlasConsole.Info($"{ctx.Host}:445", $"(enum_cve) Not vulnerable to {info.Alias} (UBR {ubr} >= {match.MinUbr})");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(enum_cve) Failed: {ex.Message}");
		}
	}

	private static async Task<bool> IsDcAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			var srvs = new Titanis.Msrpc.Mswkst.ServerServiceClient();
			await rpc.ConnectPipe(srvs, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, srvs.WellKnownPipeName ?? "srvsvc"), ct).ConfigureAwait(false);
			var shares = await srvs.GetShares(@"\\" + ctx.Host, Titanis.Msrpc.Mswkst.ShareInfoLevel.Level1, Titanis.Msrpc.Mswkst.ServerServiceClient.DefaultReturnBufferSize, ct).ConfigureAwait(false);
			return shares.Any(s => s.ShareName.Equals("SYSVOL", StringComparison.OrdinalIgnoreCase));
		}
		catch { return false; }
	}
}

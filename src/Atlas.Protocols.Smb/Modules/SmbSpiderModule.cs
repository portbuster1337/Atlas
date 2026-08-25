using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// Recursively walks readable shares and lists files, NetExec spider-style.
/// Options: depth=N (default 2), maxfiles=N (default 100), match=PATTERN (substring, case-insensitive)
/// </summary>
public sealed class SmbSpiderModule : AtlasModule<Smb2Client>
{
	public override string Name => "spider";
	public override string Description => "Recursively crawls readable shares and lists files";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		int depth = int.TryParse(ctx.Option("depth", "2"), out var d) ? Math.Max(0, d) : 2;
		int maxFiles = int.TryParse(ctx.Option("maxfiles", "100"), out var m) ? Math.Max(1, m) : 100;
		string match = ctx.Option("match", string.Empty);

		// Enumerate shares via SRVS on the same connection.
		RpcClient rpc = ctx.Services.CreateRpcClient();
		ServerServiceClient srvs = new ServerServiceClient();
		string pipe = srvs.WellKnownPipeName ?? "srvsvc";
		await rpc.ConnectPipe(srvs, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

		IList<ShareInfo> shares;
		try
		{
			shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}
		catch
		{
			shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level0, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}

		int total = 0;
		foreach (var share in shares)
		{
			if (string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase))
				continue;
			cancellationToken.ThrowIfCancellationRequested();

			try
			{
				int found = await this.SpiderShareAsync(ctx, share.ShareName, depth, maxFiles - total, match, cancellationToken).ConfigureAwait(false);
				total += found;
			}
			catch (OperationCanceledException) { throw; }
			catch { /* inaccessible share */ }
		}

		AtlasConsole.Info($"{ctx.Host}:445", $"(spider) {total} file(s) listed" +
			(match.Length > 0 ? $" matching '{match}'" : string.Empty));
	}

	private async Task<int> SpiderShareAsync(
		AtlasModuleContext<Smb2Client> ctx,
		string shareName,
		int depth,
		int remaining,
		string match,
		CancellationToken ct)
	{
		if (remaining <= 0)
			return 0;

		int count = 0;
		var queue = new Queue<(string relPath, int level)>();
		queue.Enqueue((string.Empty, 0));

		while (queue.Count > 0 && count < remaining)
		{
			ct.ThrowIfCancellationRequested();
			var (relPath, level) = queue.Dequeue();

			List<Smb2DirEntry> entries;
			try
			{
				await using Smb2Directory dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, shareName, relPath), ct).ConfigureAwait(false);
				entries = await dir.QueryDirAsync(ct).ConfigureAwait(false);
			}
			catch
			{
				continue;   // Access denied / not a directory
			}

			foreach (var e in entries)
			{
				if (e.FileName is "." or "..")
					continue;
				if (count >= remaining)
					break;

				string path = (relPath.Length == 0) ? e.FileName : $"{relPath}\\{e.FileName}";

				if (!e.IsDirectory)
				{
					if (match.Length == 0 || e.FileName.Contains(match, StringComparison.OrdinalIgnoreCase))
					{
						AtlasConsole.Info($"{ctx.Host}:445", $"(spider) {shareName}\\{path} ({e.Size} bytes)");
						count++;
					}
				}
				else if (level < depth && !e.IsReparsePoint)
				{
					queue.Enqueue((path, level + 1));
				}
			}
		}

		return count;
	}
}

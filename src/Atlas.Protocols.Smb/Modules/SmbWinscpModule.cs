using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// </summary>
public sealed class SmbWinscpModule : AtlasModule<Smb2Client>
{
    public override string Name => "winscp";
    public override string Description => "Looks for WinSCP.ini";

    public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
    {
        RpcClient rpc = ctx.Services.CreateRpcClient();
        ServerServiceClient srvs = new ServerServiceClient();
        string pipe = srvs.WellKnownPipeName ?? "srvsvc";
        await rpc.ConnectPipe(srvs, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);
        IList<ShareInfo> shares;
        try { shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false); }
        catch { shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level0, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false); }
        string[] patterns = new[] { "WinSCP.ini" };
        int found = 0;
        foreach (var share in shares)
        {
            if (share.ShareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase)) continue;
            try { found += await SpiderForPatternsAsync(ctx, share.ShareName, patterns, cancellationToken).ConfigureAwait(false); } catch {}
        }
        AtlasConsole.Info($"{ctx.Host}:445", $"(winscp) {found} file(s)");
    }

    private async Task<int> SpiderForPatternsAsync(AtlasModuleContext<Smb2Client> ctx, string share, string[] patterns, CancellationToken ct)
    {
        int count = 0;
        var queue = new Queue<(string rel, int level)>();
        queue.Enqueue((string.Empty, 0));
        const int maxDepth = 3, maxFiles = 200;
        int visited = 0;
        while (queue.Count > 0 && visited < maxFiles)
        {
            ct.ThrowIfCancellationRequested();
            var (rel, level) = queue.Dequeue();
            List<Smb2DirEntry> entries;
            try
            {
                await using var dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, share, rel), ct).ConfigureAwait(false);
                entries = await dir.QueryDirAsync(ct).ConfigureAwait(false);
            }
            catch { continue; }
            foreach (var e in entries)
            {
                if (e.FileName is "." or "..") continue;
                string child = rel.Length == 0 ? e.FileName : $"{rel}\\{e.FileName}";
                if (!e.IsDirectory)
                {
                    if (patterns.Any(p => e.FileName.Contains(p, StringComparison.OrdinalIgnoreCase)))
                    {
                        AtlasConsole.Success($"{ctx.Host}:445", $"(winscp) {share}\\{child} ({e.Size} bytes)");
                        count++;
                    }
                }
                else if (level < maxDepth && !e.IsReparsePoint) queue.Enqueue((child, level + 1));
                visited++;
                if (visited >= maxFiles) break;
            }
        }
        return count;
    }
}

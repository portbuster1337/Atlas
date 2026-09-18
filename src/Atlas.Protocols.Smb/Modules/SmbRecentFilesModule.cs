using System.Text;
using Titanis;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec recent_files: parses Recent/*.lnk targets for all users.
/// </summary>
public sealed class SmbRecentFilesModule : AtlasModule<Smb2Client>
{
	public override string Name => "recent_files";
	public override string Description => "Lists recently opened files (Recent/*.lnk) for all users";

	private static readonly string[] SkipUsers = new[] { ".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic" };

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		var seen = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			await using var usersDir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", "Users"), cancellationToken).ConfigureAwait(false);
			foreach (var u in await usersDir.QueryDirAsync(cancellationToken).ConfigureAwait(false))
			{
				if (!u.IsDirectory || SkipUsers.Contains(u.FileName, StringComparer.OrdinalIgnoreCase)) continue;
				string recent = $"Users\\{u.FileName}\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
				List<Smb2DirEntry> entries;
				try
				{
					await using var rd = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", recent), cancellationToken).ConfigureAwait(false);
					entries = await rd.QueryDirAsync(cancellationToken).ConfigureAwait(false);
				}
				catch { continue; }
				foreach (var e in entries)
				{
					if (e.IsDirectory || !e.FileName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) continue;
					try
					{
						byte[] lnk = await ReadFileAsync(ctx, "C$", $"{recent}\\{e.FileName}", cancellationToken).ConfigureAwait(false);
						string? target = ExtractLnkTarget(lnk);
						if (target is not null && seen.Add(target))
							AtlasConsole.Success($"{ctx.Host}:445", $"(recent_files) {u.FileName}: {target}");
					}
					catch { }
				}
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(recent_files) {seen.Count} unique recent file(s)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(recent_files) Failed: {ex.Message}");
		}
	}

	private static async Task<byte[]> ReadFileAsync(AtlasModuleContext<Smb2Client> ctx, string share, string path, CancellationToken ct)
	{
		await using var stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, share, path), ct).ConfigureAwait(false);
		using var ms = new MemoryStream();
		await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
		return ms.ToArray();
	}

	private static string? ExtractLnkTarget(byte[] lnk)
	{
		if (lnk.Length < 76 || lnk[0] != 0x4C) return null;
		// ShellLinkHeader (76B): LinkFlags @0x14, then LinkTargetIDList (if 0x01) starting @76
		uint flags = BitConverter.ToUInt32(lnk, 0x14);
		int off = 76;
		if ((flags & 0x01) != 0)
		{
			if (off + 2 > lnk.Length) return null;
			ushort idListSize = BitConverter.ToUInt16(lnk, off);
			off += 2 + idListSize;
		}
		// Best-effort: scan remainder for longest drive-letter or UNC path string
		string ascii = Encoding.ASCII.GetString(lnk, Math.Min(off, lnk.Length), Math.Max(0, lnk.Length - Math.Min(off, lnk.Length)));
		string uni = Encoding.Unicode.GetString(lnk);
		string? best = null;
		foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(ascii + "\n" + uni, @"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.$-]+\\[A-Za-z0-9_.$-]+)[^<>:\""/\\|?*\x00-\x1F]*"))
		{
			string s = m.Value.TrimEnd(' ', '.');
			if (s.Length > (best?.Length ?? 0)) best = s;
		}
		return best;
	}
}

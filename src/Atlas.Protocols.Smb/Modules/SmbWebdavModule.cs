using Titanis;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec webdav: checks if the WebClient service is running (WebDAV coercion possible).
/// </summary>
public sealed class SmbWebdavModule : AtlasModule<Smb2Client>
{
	public override string Name => "webdav";
	public override string Description => "Checks if WebClient (WebDAV) is running via IPC$ DAV RPC Service";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			var create = new Smb2CreateInfo
			{
				OplockLevel = Smb2OplockLevel.None,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				DesiredAccess = (uint)Smb2FileAccessRights.ReadData,
				FileAttributes = Titanis.Winterop.FileAttributes.Normal,
				ShareAccess = Smb2ShareAccess.ReadWriteDelete,
				CreateDisposition = Smb2CreateDisposition.OpenExisting,
				CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
			};
			await using var f = await ctx.Client.CreateFileAsync(
				new UncPath(ctx.Host, Smb2Client.IpcName, "DAV RPC Service"), create, FileAccess.Read, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:445", "(webdav) WebClient Service is ENABLED (DAV RPC Service reachable - WebDAV coercion possible)");
		}
		catch (Exception ex) when (ex.Message.Contains("NOT_FOUND", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("0xC0000034") || ex.Message.Contains("OBJECT_NAME_NOT_FOUND", StringComparison.OrdinalIgnoreCase))
		{
			AtlasConsole.Info($"{ctx.Host}:445", "(webdav) WebClient Service not running (DAV RPC Service not found)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Info($"{ctx.Host}:445", $"(webdav) inconclusive: {ex.Message}");
		}
	}
}

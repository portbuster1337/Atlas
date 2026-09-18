using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Mslsar;
using Titanis.Smb2;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec enum_av: detects installed/running AV/EDR via LSA service lookups + IPC$ pipes.
/// </summary>
public sealed class SmbEnumAvModule : AtlasModule<Smb2Client>
{
	public override string Name => "enum_av";
	public override string Description => "Detects AV/EDR products via LSA service names and IPC$ pipes (no privs needed)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		try
		{
			// 1. LSA lookups: "NT Service\<ServiceName>"
			try
			{
				RpcClient rpc = ctx.Services.CreateRpcClient();
				rpc.DefaultAuthLevel = Titanis.DceRpc.RpcAuthLevel.None;
				var lsaClient = new LsaClient();
				await rpc.ConnectPipe(lsaClient, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, LsaClient.LsaPipeName), cancellationToken).ConfigureAwait(false);
				using var policy = await lsaClient.OpenPolicy(LsaPolicyAccess.LookupNames, cancellationToken).ConfigureAwait(false);
				foreach (var product in SmbEnumAvData.Products)
				{
					foreach (var svc in product.Services)
					{
						cancellationToken.ThrowIfCancellationRequested();
						try
						{
							await policy.ResolveAccountName($"NT Service\\{svc.Name}", cancellationToken).ConfigureAwait(false);
							if (found.Add(product.Name))
								AtlasConsole.Success($"{ctx.Host}:445", $"(enum_av) Detected installed: {product.Name} ({svc.Description})");
						}
						catch { }
					}
				}
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{ctx.Host}:445", $"(enum_av) LSA lookup path failed: {ex.Message}");
			}

			// 2. IPC$ pipe listing for running claims
			try
			{
				await using var dir = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, Smb2Client.IpcName, string.Empty), cancellationToken).ConfigureAwait(false);
				var entries = await dir.QueryDirAsync(cancellationToken).ConfigureAwait(false);
				foreach (var e in entries)
				{
					if (e.FileName is "." or "..") continue;
					foreach (var product in SmbEnumAvData.Products)
					{
						foreach (var pipe in product.Pipes)
						{
							if (GlobMatch(pipe.Pattern, e.FileName))
							{
								string procs = (pipe.Processes.Length > 0) ? $" (likely {string.Join(",", pipe.Processes)})" : string.Empty;
								AtlasConsole.Success($"{ctx.Host}:445", $"(enum_av) {product.Name} running claim via pipe {e.FileName}{procs}");
								found.Add(product.Name);
							}
						}
					}
				}
			}
			catch (Exception ex)
			{
				AtlasConsole.Warn($"{ctx.Host}:445", $"(enum_av) IPC$ pipe listing failed: {ex.Message}");
			}

			if (found.Count == 0)
				AtlasConsole.Info($"{ctx.Host}:445", "(enum_av) Found NOTHING!");
			else
				AtlasConsole.Info($"{ctx.Host}:445", $"(enum_av) {found.Count} product(s) detected: {string.Join(", ", found)}");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(enum_av) Failed: {ex.Message}");
		}
	}

	private static bool GlobMatch(string pattern, string name)
	{
		// NetExec uses PurePath.match semantics (* matches across separators); approximate with fnmatch-style.
		string regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
		return System.Text.RegularExpressions.Regex.IsMatch(name, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
	}
}

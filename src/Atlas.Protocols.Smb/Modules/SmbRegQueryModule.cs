using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec reg-query: query/set/delete registry values.
/// Options: PATH=<hive\key> (required), KEY=<value name>, VALUE=<data>, TYPE=<REG_SZ|...>, DELETE=True.
/// </summary>
public sealed class SmbRegQueryModule : AtlasModule<Smb2Client>
{
	public override string Name => "reg-query";
	public override string Description => "Queries (and optionally sets/deletes) registry values (PATH=..., KEY=..., VALUE=..., TYPE=..., DELETE=True)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		string path = ctx.Option("PATH", "");
		string keyName = ctx.Option("KEY", "");
		string value = ctx.Option("VALUE", "");
		string type = ctx.Option("TYPE", "REG_SZ").Trim().ToUpperInvariant();
		bool delete = ctx.Option("DELETE", "").Equals("True", StringComparison.OrdinalIgnoreCase);
		if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(keyName))
		{
			AtlasConsole.Fail($"{ctx.Host}:445", "(reg-query) PATH and KEY are required (e.g. -mo PATH=HKLM\\SOFTWARE\\X,KEY=Name)");
			return;
		}
		try
		{
			var parsed = RegistryPath.Parse(path);
			RpcClient rpc = ctx.Services.CreateRpcClient();
			using RemoteRegistryClient reg = new RemoteRegistryClient();
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
			await using var root = await reg.OpenRootKey(parsed.Root, RegistryAccessRights.KeyAll, cancellationToken).ConfigureAwait(false);
			RegistryKey? subkey = null;
			try
			{
				subkey = parsed.IsRootPath ? null : await root.OpenSubkey(parsed.KeyPath, RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex) when (IsNotFound(ex))
			{
				if (delete || string.IsNullOrEmpty(value) && !ctx.Options.ContainsKey("VALUE"))
					throw;
				subkey = await root.CreateSubkey(parsed.KeyPath, RegistryAccessRights.KeyAll, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				AtlasConsole.Info($"{ctx.Host}:445", $"(reg-query) created key {path}");
			}
			if (parsed.IsRootPath)
			{
				await DumpKeyAsync(ctx, path, root, keyName, value, type, delete, cancellationToken).ConfigureAwait(false);
				return;
			}
			await using (subkey!)
			{
				await DumpKeyAsync(ctx, path, subkey!, keyName, value, type, delete, cancellationToken).ConfigureAwait(false);
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(reg-query) Failed: {ex.Message}");
		}
	}

	private static bool IsNotFound(Exception ex) =>
		ex.Message.Contains("NOT_FOUND", StringComparison.OrdinalIgnoreCase)
		|| ex.Message.Contains("0x00000002", StringComparison.OrdinalIgnoreCase)
		|| ex.Message.Contains("cannot find", StringComparison.OrdinalIgnoreCase);

	private static async Task DumpKeyAsync(AtlasModuleContext<Smb2Client> ctx, string path, RegistryKey key, string keyName, string value, string type, bool delete, CancellationToken ct)
	{
		if (delete)
		{
			await key.DeleteValue(keyName, ct).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:445", $"(reg-query) deleted {path}!{keyName}");
			return;
		}
		if (!string.IsNullOrEmpty(value) || ctx.Options.ContainsKey("VALUE"))
		{
			var (kind, data) = EncodeValue(type, value);
			await key.SetValue(keyName, kind, data, ct).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:445", $"(reg-query) set {path}!{keyName} [{kind}] = {value}");
			return;
		}
		try
		{
			var v = await key.GetValue(keyName, ct).ConfigureAwait(false);
			AtlasConsole.Success($"{ctx.Host}:445", $"(reg-query) {path}!{v.Name} [{v.ValueType}] = {Fmt(v)}");
		}
		catch
		{
			AtlasConsole.Info($"{ctx.Host}:445", $"(reg-query) listing values under {path}:");
			await foreach (var v in key.GetValues(true, ct).ConfigureAwait(false))
				AtlasConsole.Info($"{ctx.Host}:445", $"(reg-query)   {v.Name} [{v.ValueType}] = {Fmt(v)}");
		}
	}

	private static (RegistryValueType Kind, byte[] Data) EncodeValue(string type, string value) => type switch
	{
		"REG_DWORD" or "DWORD" => (RegistryValueType.DwordLE, BitConverter.GetBytes(uint.TryParse(value, out var u) ? u : 0u)),
		"REG_QWORD" or "QWORD" => (RegistryValueType.Qword, BitConverter.GetBytes(ulong.TryParse(value, out var q) ? q : 0ul)),
		"REG_BINARY" or "BINARY" => (RegistryValueType.Binary, Convert.FromHexString(value.Replace(" ", "", StringComparison.Ordinal))),
		"REG_MULTI_SZ" or "MULTI_SZ" => (RegistryValueType.MultiString, System.Text.Encoding.Unicode.GetBytes(string.Join('\0', value.Split(';')) + "\0\0")),
		"REG_EXPAND_SZ" or "EXPAND_SZ" => (RegistryValueType.ExpandString, System.Text.Encoding.Unicode.GetBytes(value + '\0')),
		_ => (RegistryValueType.String, System.Text.Encoding.Unicode.GetBytes(value + '\0')),
	};

	private static string Fmt(RegistryValueInfo v)
	{
		if (v.TypedValue is not null) return v.TypedValue.ToString() ?? string.Empty;
		if (v.Bytes is not null) return Convert.ToHexString(v.Bytes);
		return string.Empty;
	}
}

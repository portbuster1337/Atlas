using Titanis.Msrpc;
using Titanis.DceRpc;
using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Msrrp;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// </summary>
public sealed class SmbEnumInterfacesModule : AtlasModule<Smb2Client>
{
	public override string Name => "enum_interfaces";
	public override string Description => "Enumerates network interfaces via registry (IP, subnet, gateway)";

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			using var reg = await BindWinregAsync(ctx, cancellationToken).ConfigureAwait(false);
			await using var lm = await reg.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);
			// Enumerate interfaces under SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
			string basePath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
			await using var ifaceRoot = await TryOpen(lm, basePath, cancellationToken).ConfigureAwait(false);
			if (ifaceRoot == null)
			{
				AtlasConsole.Fail($"{ctx.Host}:445", "(enum_interfaces) Interfaces key not found");
				return;
			}
			var subkeys = new List<string>();
			await foreach (var sub in ifaceRoot.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
				subkeys.Add(sub.KeyName);

			if (subkeys.Count == 0)
			{
				AtlasConsole.Info($"{ctx.Host}:445", "(enum_interfaces) No interfaces found");
				return;
			}
			foreach (var guid in subkeys)
			{
				await using var ifaceKey = await TryOpen(ifaceRoot, guid, cancellationToken).ConfigureAwait(false);
				if (ifaceKey == null) continue;
				string dhcpIp = await TryGetString(ifaceKey, "DhcpIPAddress", cancellationToken).ConfigureAwait(false) ?? "";
				string ip = await TryGetString(ifaceKey, "IPAddress", cancellationToken).ConfigureAwait(false) ?? dhcpIp;
				string mask = await TryGetString(ifaceKey, "DhcpSubnetMask", cancellationToken).ConfigureAwait(false) ?? await TryGetString(ifaceKey, "SubnetMask", cancellationToken).ConfigureAwait(false) ?? "";
				string gw = await TryGetString(ifaceKey, "DhcpDefaultGateway", cancellationToken).ConfigureAwait(false) ?? await TryGetString(ifaceKey, "DefaultGateway", cancellationToken).ConfigureAwait(false) ?? "";
				string dhcpServer = await TryGetString(ifaceKey, "DhcpServer", cancellationToken).ConfigureAwait(false) ?? "";
				AtlasConsole.Info($"{ctx.Host}:445", $"(enum_interfaces) {guid}: IP={ip} Mask={mask} GW={gw} DHCPServer={dhcpServer}");
			}
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(enum_interfaces) Failed: {ex.Message}");
		}
	}

	private static async Task<IRegistryKey?> TryOpen(IRegistryKey baseKey, string path, CancellationToken ct)
	{
		try { return await baseKey.OpenSubkey(path, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, ct).ConfigureAwait(false); }
		catch { return null; }
	}

	private static async Task<string?> TryGetString(IRegistryKey key, string name, CancellationToken ct)
	{
		try
		{
			var v = await key.GetValue(name, ct).ConfigureAwait(false);
			if (v.TypedValue is string s) return s;
			if (v.TypedValue is string[] arr) return string.Join(",", arr);
			if (v.Bytes != null) return System.Text.Encoding.Unicode.GetString(v.Bytes).TrimEnd('\0');
			return v.TypedValue?.ToString();
		}
		catch { return null; }
	}

	private static async Task<RemoteRegistryClient> BindWinregAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken ct)
	{
		RpcClient rpc = ctx.Services.CreateRpcClient();
		RemoteRegistryClient client = new RemoteRegistryClient();
		string pipe = client.WellKnownPipeName ?? "winreg";
		await rpc.ConnectPipe(client, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, pipe), ct).ConfigureAwait(false);
		return client;
	}
}

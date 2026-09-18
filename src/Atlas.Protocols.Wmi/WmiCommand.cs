using System.ComponentModel;
using Titanis.Cli;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.DceRpc.Epm;
using Titanis.Msrpc.Msdcom;
using Titanis.Msrpc.Mswmi;

namespace Atlas.Protocols;

/// <summary>
/// execute commands via Win32_Process.Create, built on Titanis DCOM/WMI.
/// </summary>
[Description("Interacts with WMI services (auth check, remote exec)")]
public sealed class WmiCommand : Command
{
	[Parameter(0)]
	[Mandatory]
	[Placeholder("targets")]
	[Description("Targets as host, IP, CIDR, range (a.b.c.d-e), comma list, or @file")]
	public string TargetSpec { get; set; } = null!;

	[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
	public RpcParameterGroup RpcParameters { get; set; } = null!;

	[Parameter]
	[Alias("x")]
	[Description("Command line to execute via Win32_Process.Create")]
	public string? Exec { get; set; }

	[Parameter]
	[Description("PowerShell command to execute via Win32_Process.Create")]
	public string? PsExec { get; set; }

	[Parameter]
	[Description("Working directory for the executed command")]
	public string? WorkingDir { get; set; }

	[Parameter]
	[Alias("wmi-query")]
	public string? WmiQuery { get; set; }

	[Parameter]
	[Alias("wmi-namespace")]
	[Description("WMI namespace (default: root\\cimv2)")]
	public string? WmiNamespace { get; set; }

	[Parameter]
	[Alias("wmi-namespaces")]
	[Description("List child namespaces of -wmi-namespace (default: root\\cimv2)")]
	public SwitchParam WmiNamespaces { get; set; }

	[Parameter]
	[Alias("wmi-reg-query")]
	[Description("Query registry via StdRegProv (e.g. HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion)")]
	public string? WmiRegQuery { get; set; }

	[Parameter]
	[Alias("wmi-reg-value")]
	[Description("Read a single registry value (use with -wmi-reg-query <key>)")]
	public string? WmiRegValue { get; set; }

	[Parameter]
	[Alias("dcom-clsid")]
	[Description("Activate a COM object by CLSID via DCOM (use with -dcom-method)")]
	public string? DcomClsid { get; set; }

	[Parameter]
	[Alias("dcom-method")]
	[Description("Method/property path to invoke on the activated object (e.g. Document.ActiveView.ExecuteShellCommand)")]
	public string? DcomMethod { get; set; }

	[Parameter]
	[Alias("dcom-args")]
	[Description("Comma-separated string arguments for -dcom-method")]
	public string? DcomArgs { get; set; }

	[Parameter]
	[Alias("epm-list")]
	[Description("Enumerate RPC endpoints via the endpoint mapper (port 135)")]
	public SwitchParam EpmList { get; set; }

	[Parameter]
	[DefaultValue(1)]
	[Alias("t")]
	[Description("Number of concurrent targets")]
	public int Threads { get; set; } = 1;

	[Parameter]
	[DefaultValue(30)]
	[Description("Per-host timeout in seconds")]
	public int Timeout { get; set; } = 30;

	private const int WmiPort = 135;

	protected override void ValidateParameters(ParameterValidationContext context)
	{
		var rpcParams = this.RpcParameters;
		rpcParams.Authentication?.Validate(!this.AuthenticationRequired(), context);

		try
		{
			var targets = TargetList.Parse(this.TargetSpec);
			if (targets.Count == 0)
				context.LogError(nameof(this.TargetSpec), "No valid targets specified");
		}
		catch (Exception ex)
		{
			context.LogError(nameof(this.TargetSpec), ex.Message);
		}

		if (this.WmiQuery is not null && (this.Exec is not null || this.PsExec is not null))
			context.LogError(nameof(this.WmiQuery), "--wmi-query and -x/-X are mutually exclusive");
		if (this.Exec is not null && this.PsExec is not null)
			context.LogError(nameof(this.Exec), "-x and -X are mutually exclusive");

		int modes = 0;
		if (this.Exec is not null || this.PsExec is not null) modes++;
		if (this.WmiQuery is not null) modes++;
		if (this.WmiNamespaces.IsSet) modes++;
		if (this.WmiRegQuery is not null) modes++;
		if (this.DcomClsid is not null || this.DcomMethod is not null) modes++;
		if (this.EpmList.IsSet) modes++;
		if (modes > 1)
			context.LogError(nameof(this.Exec), "-x, -wmi-query, -wmi-namespaces, -wmi-reg-query, -dcom-clsid/-dcom-method, and -epm-list are mutually exclusive");

		if (this.DcomMethod is not null && this.DcomClsid is null)
			context.LogError(nameof(this.DcomClsid), "-dcom-method requires -dcom-clsid <guid>");
		if (this.DcomArgs is not null && this.DcomMethod is null)
			context.LogError(nameof(this.DcomMethod), "-dcom-args requires -dcom-method");
		if (this.DcomClsid is not null)
		{
			if (!Guid.TryParse(this.DcomClsid, out _))
				context.LogError(nameof(this.DcomClsid), "-dcom-clsid is not a valid GUID");
			if (this.DcomMethod is null)
				context.LogError(nameof(this.DcomMethod), "-dcom-clsid requires -dcom-method");
		}
		if (this.WmiRegValue is not null && this.WmiRegQuery is null)
			context.LogError(nameof(this.WmiRegQuery), "-wmi-reg-value requires -wmi-reg-query <key>");
	}

	private bool AuthenticationRequired()
		=> !this.RpcParameters.Authentication.Anonymous.IsSet;

	protected sealed override async Task<int> RunAsync(CancellationToken cancellationToken)
	{
		var targets = TargetList.Parse(this.TargetSpec);
		int failures = 0;

		await Parallel.ForEachAsync(
			targets,
			new ParallelOptions
			{
				MaxDegreeOfParallelism = this.Threads,
				CancellationToken = cancellationToken,
			},
			async (host, token) =>
			{
				using var timeoutCts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(token);
				timeoutCts.CancelAfter(TimeSpan.FromSeconds(this.Timeout));
				try
				{
					await this.ProcessHostAsync(host, timeoutCts.Token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (token.IsCancellationRequested)
				{
					throw;
				}
				catch (OperationCanceledException)
				{
					Interlocked.Increment(ref failures);
					AtlasConsole.Fail($"{host}:{WmiPort}", $"No response within {this.Timeout}s (timeout)");
				}
				catch (Exception ex)
				{
					Interlocked.Increment(ref failures);
					string msg = this.Verbose.IsSet ? ex.ToString() : ex.Message;
					AtlasConsole.Fail($"{host}:{WmiPort}", msg);
				}
			}).ConfigureAwait(false);

		return failures > 0 ? 1 : 0;
	}

	private async Task ProcessHostAsync(string host, CancellationToken cancellationToken)
	{
		if (this.EpmList.IsSet)
		{
			await this.EpmListAsync(host, cancellationToken).ConfigureAwait(false);
			return;
		}

		if (this.DcomClsid is not null)
		{
			await this.DcomInvokeAsync(host, cancellationToken).ConfigureAwait(false);
			return;
		}

		WmiClient wmi = await this.ConnectAsync(host, cancellationToken).ConfigureAwait(false);

		if (this.WmiNamespaces.IsSet)
		{
			await this.ListNamespacesAsync(wmi, host, cancellationToken).ConfigureAwait(false);
			return;
		}

		if (this.WmiRegQuery is not null)
		{
			await this.RegQueryAsync(wmi, host, cancellationToken).ConfigureAwait(false);
			return;
		}

		if (this.WmiQuery is not null)
		{
			string nsName = string.IsNullOrWhiteSpace(this.WmiNamespace) ? WmiClient.RootCimV2Namespace : this.WmiNamespace!;
			var scope = await wmi.OpenNamespace(nsName, "en-US", cancellationToken).ConfigureAwait(false);
			AtlasConsole.Info($"{host}:{WmiPort}", $"WQL query: {this.WmiQuery} (ns={nsName})");
			var reader = await scope.ExecuteWqlQueryAsync(this.WmiQuery!, 20, cancellationToken).ConfigureAwait(false);
			int count = 0;
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				var obj = reader.Current;
				if (obj is null) continue;
				count++;
				var props = new List<string>();
				if (obj is WmiInstanceObject inst)
				{
					foreach (var prop in inst.Properties)
					{
						string val = prop.Value?.ToString() ?? "";
						string name = prop.ClassProperty?.Name ?? "unknown";
						if (val.Length > 80) val = val[..80] + "...";
						props.Add($"{name}={val}");
					}
				}
				else if (obj is WmiClassObject cls)
				{
					foreach (var prop in cls.Properties)
					{
						string val = prop.DefaultValue?.ToString() ?? "";
						string name = prop.Name ?? "unknown";
						if (val.Length > 80) val = val[..80] + "...";
						props.Add($"{name}={val}");
					}
				}
				else
				{
					props.Add(obj.ToString() ?? "");
				}
				AtlasConsole.Info($"{host}:{WmiPort}", $"[{count}] {string.Join("; ", props)}");
				if (count >= 100)
				{
					AtlasConsole.Info($"{host}:{WmiPort}", "Truncated at 100 results");
					break;
				}
			}
			AtlasConsole.Info($"{host}:{WmiPort}", $"WQL done: {count} object(s)");
			return;
		}

		if (this.Exec is null && this.PsExec is null)
		{
			AtlasConsole.Success($"{host}:{WmiPort}", "authenticated");
			return;
		}

		var ns2 = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
		var processClass = (WmiClassObject)await ns2.GetObjectAsync("Win32_Process", cancellationToken).ConfigureAwait(false);

		string cmdLine = this.Exec ?? $"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"{this.PsExec!.Replace("\"", "\\\"")}\"";
		var args = new Dictionary<string, object?>();
		if (!string.IsNullOrEmpty(this.WorkingDir))
			args["CurrentDirectory"] = this.WorkingDir;
		args["CommandLine"] = cmdLine;

		WmiInstanceObject result = await processClass.InvokeMethodAsync("Create", args, cancellationToken).ConfigureAwait(false);

		uint returnValue = Convert.ToUInt32(result["ReturnValue"] ?? 0U);
		uint pid = Convert.ToUInt32(result["ProcessId"] ?? 0U);
		if (returnValue != 0)
		{
			AtlasConsole.Fail($"{host}:{WmiPort}", $"process creation failed (ReturnValue={returnValue})");
			return;
		}

		AtlasConsole.Success($"{host}:{WmiPort}", $"exec: PID={pid} - '{cmdLine}'");
	}

	private async Task ListNamespacesAsync(WmiClient wmi, string host, CancellationToken cancellationToken)
	{
		string nsName = string.IsNullOrWhiteSpace(this.WmiNamespace) ? WmiClient.RootCimV2Namespace : this.WmiNamespace!;
		var scope = await wmi.OpenNamespace(nsName, "en-US", cancellationToken).ConfigureAwait(false);
		var reader = await scope.ExecuteWqlQueryAsync("SELECT * FROM __NAMESPACE", 20, cancellationToken).ConfigureAwait(false);
		int count = 0;
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			if (reader.Current is WmiInstanceObject inst)
			{
				foreach (var prop in inst.Properties)
				{
					if (prop.ClassProperty?.Name == "Name")
					{
						AtlasConsole.Success($"{host}:{WmiPort}", $"namespace: {nsName}\\{prop.Value}");
						count++;
					}
				}
			}
		}
		AtlasConsole.Info($"{host}:{WmiPort}", $"--wmi-namespaces: {count} namespace(s) under {nsName}");
	}

	private static uint ParseHive(string hive) => hive.ToUpperInvariant() switch
	{
		"HKCR" or "HKEY_CLASSES_ROOT" => 0x80000000u,
		"HKCU" or "HKEY_CURRENT_USER" => 0x80000001u,
		"HKLM" or "HKEY_LOCAL_MACHINE" => 0x80000002u,
		"HKU" or "HKEY_USERS" => 0x80000003u,
		"HKCC" or "HKEY_CURRENT_CONFIG" => 0x80000005u,
		_ => throw new ArgumentException($"Unknown registry hive '{hive}' (use HKLM, HKCU, HKCR, HKU, or HKCC)"),
	};

	private async Task RegQueryAsync(WmiClient wmi, string host, CancellationToken cancellationToken)
	{
		string spec = this.WmiRegQuery!;
		int sep = spec.IndexOf('\\');
		if (sep < 0)
			throw new ArgumentException("-wmi-reg-query must be HIVE\\key (e.g. HKLM\\SOFTWARE\\Microsoft)");
		uint hDefKey = ParseHive(spec[..sep]);
		string subKey = spec[(sep + 1)..];

		var scope = await wmi.OpenNamespace("root\\default", "en-US", cancellationToken).ConfigureAwait(false);
		var prov = (WmiClassObject)await scope.GetObjectAsync("StdRegProv", cancellationToken).ConfigureAwait(false);

		if (this.WmiRegValue is not null)
		{
			await this.RegGetValueAsync(prov, host, hDefKey, subKey, this.WmiRegValue, cancellationToken).ConfigureAwait(false);
			return;
		}

		WmiInstanceObject subkeys = await prov.InvokeMethodAsync("EnumKey",
			new Dictionary<string, object?> { ["hDefKey"] = hDefKey, ["sSubKeyName"] = subKey }, cancellationToken).ConfigureAwait(false);
		if (Convert.ToUInt32(subkeys["ReturnValue"] ?? 1u) != 0)
			AtlasConsole.Fail($"{host}:{WmiPort}", $"EnumKey failed for {spec} (ReturnValue={subkeys["ReturnValue"]})");
		else
			foreach (var line in FormatWmiStringArray(subkeys["sNames"]))
				AtlasConsole.Success($"{host}:{WmiPort}", $"[{spec}] subkey: {line}");

		WmiInstanceObject values = await prov.InvokeMethodAsync("EnumValues",
			new Dictionary<string, object?> { ["hDefKey"] = hDefKey, ["sSubKeyName"] = subKey }, cancellationToken).ConfigureAwait(false);
		if (Convert.ToUInt32(values["ReturnValue"] ?? 1u) != 0)
		{
			AtlasConsole.Fail($"{host}:{WmiPort}", $"EnumValues failed for {spec} (ReturnValue={values["ReturnValue"]})");
			return;
		}
		var names = ToStringList(values["sNames"]);
		var types = ToUIntList(values["Types"]);
		for (int i = 0; i < names.Count; i++)
		{
			uint type = (i < types.Count) ? types[i] : 0;
			AtlasConsole.Success($"{host}:{WmiPort}", $"[{spec}] value: {names[i]} (type={RegValueTypeName(type)})");
		}
		AtlasConsole.Info($"{host}:{WmiPort}", $"--wmi-reg-query: {names.Count} value(s) under {spec}");
	}

	private async Task RegGetValueAsync(WmiClassObject prov, string host, uint hDefKey, string subKey, string valueName, CancellationToken cancellationToken)
	{
		WmiInstanceObject types = await prov.InvokeMethodAsync("EnumValues",
			new Dictionary<string, object?> { ["hDefKey"] = hDefKey, ["sSubKeyName"] = subKey }, cancellationToken).ConfigureAwait(false);
		uint type = 1;
		var names = ToStringList(types["sNames"]);
		var typeList = ToUIntList(types["Types"]);
		for (int i = 0; i < names.Count; i++)
		{
			if (names[i].Equals(valueName, StringComparison.OrdinalIgnoreCase) && i < typeList.Count)
			{
				type = typeList[i];
				break;
			}
		}
		string method = type switch
		{
			4 => "GetDWORDValue",
			11 => "GetQWORDValue",
			3 => "GetBinaryValue",
			7 => "GetMultiStringValue",
			2 => "GetExpandedStringValue",
			_ => "GetStringValue",
		};
		WmiInstanceObject result = await prov.InvokeMethodAsync(method,
			new Dictionary<string, object?> { ["hDefKey"] = hDefKey, ["sSubKeyName"] = subKey, ["sValueName"] = valueName }, cancellationToken).ConfigureAwait(false);
		if (Convert.ToUInt32(result["ReturnValue"] ?? 1u) != 0)
		{
			AtlasConsole.Fail($"{host}:{WmiPort}", $"{method} failed for {valueName} (ReturnValue={result["ReturnValue"]})");
			return;
		}
		foreach (var prop in result.Properties)
		{
			string name = prop.ClassProperty?.Name ?? "unknown";
			if (name == "ReturnValue") continue;
			AtlasConsole.Success($"{host}:{WmiPort}", $"{valueName} [{method}] = {FormatWmiValue(prop.Value)}");
		}
	}

	private static List<string> ToStringList(object? value)
	{
		var list = new List<string>();
		if (value is System.Collections.IEnumerable en && value is not string)
			foreach (var o in en) list.Add(o?.ToString() ?? string.Empty);
		else if (value is not null) list.Add(value.ToString() ?? string.Empty);
		return list;
	}

	private static List<uint> ToUIntList(object? value)
	{
		var list = new List<uint>();
		if (value is System.Collections.IEnumerable en && value is not string)
			foreach (var o in en)
			{
				try { list.Add(Convert.ToUInt32(o)); } catch { }
			}
		return list;
	}

	private static IEnumerable<string> FormatWmiStringArray(object? value)
	{
		foreach (var s in ToStringList(value))
			yield return s;
	}

	private static string FormatWmiValue(object? value) => value switch
	{
		null => string.Empty,
		byte[] b => Convert.ToHexString(b),
		System.Collections.IEnumerable en when value is not string => string.Join(", ", en.Cast<object>().Select(o => o?.ToString() ?? string.Empty)),
		_ => value.ToString() ?? string.Empty,
	};

	private static string RegValueTypeName(uint type) => type switch
	{
		1 => "REG_SZ",
		2 => "REG_EXPAND_SZ",
		3 => "REG_BINARY",
		4 => "REG_DWORD",
		7 => "REG_MULTI_SZ",
		11 => "REG_QWORD",
		_ => $"type={type}",
	};

	private async Task DcomInvokeAsync(string host, CancellationToken cancellationToken)
	{
		var rpcParams = this.RpcParameters;
		if (rpcParams.NetParameters.HostAddress is null || rpcParams.NetParameters.HostAddress.Length == 0)
			rpcParams.NetParameters.HostAddress = new[] { host };

		RpcClient rpcClient = this.Services.CreateRpcClient();
		rpcParams.ApplyTo(rpcClient, RpcAuthLevel.PacketIntegrity);
		if (!rpcParams.OfferNdr64.IsSpecified)
			rpcClient.OfferNdr64 = false; // NDR32 default: Titanis NDR64 DCOM fails on Server 2025+ (RPC 1783)

		DcomClient dcom = await DcomClient.ConnectTo(host, rpcClient, cancellationToken).ConfigureAwait(false);
		var obj = await dcom.Activate(Guid.Parse(this.DcomClsid!), cancellationToken).ConfigureAwait(false);

		string method = this.DcomMethod!;
		int isep = method.LastIndexOf('.');
		if (isep != -1)
		{
			foreach (var prop in method[..isep].Split('.', StringSplitOptions.RemoveEmptyEntries))
			{
				var propValue = await obj.InvokeMethod(prop, Array.Empty<string>(), cancellationToken).ConfigureAwait(false);
				if (propValue is OleAutomationObject child)
					obj = child;
				else
					throw new InvalidOperationException($"Property '{prop}' did not return an automation object (got {(propValue?.GetType().FullName ?? "<null>")})");
			}
			method = method[(isep + 1)..];
		}

		object[] args = (this.DcomArgs is null)
			? Array.Empty<object>()
			: this.DcomArgs.Split(',', StringSplitOptions.TrimEntries).Cast<object>().ToArray();
		var result = await obj.InvokeMethod(method, args, cancellationToken).ConfigureAwait(false);
		AtlasConsole.Success($"{host}:{WmiPort}", $"dcom {this.DcomClsid}::{this.DcomMethod} -> {(result?.ToString() ?? "<null>")}");
	}

	private async Task EpmListAsync(string host, CancellationToken cancellationToken)
	{
		var rpcParams = this.RpcParameters;
		if (rpcParams.NetParameters.HostAddress is null || rpcParams.NetParameters.HostAddress.Length == 0)
			rpcParams.NetParameters.HostAddress = new[] { host };

		RpcClient rpcClient = this.Services.CreateRpcClient();
		rpcParams.ApplyTo(rpcClient, RpcAuthLevel.PacketIntegrity);

		EpmClient epm = new EpmClient();
		var bindInfo = await rpcParams.BindServiceClient(epm, host, cancellationToken).ConfigureAwait(false);
		using (bindInfo.SmbClient)
		{
			var entries = await epm.Lookup(32, null, null, InquiryVersionOptions.All, default, cancellationToken).ConfigureAwait(false);
			foreach (var entry in entries)
				AtlasConsole.Success($"{host}:{WmiPort}", entry.ToString());
			AtlasConsole.Info($"{host}:{WmiPort}", $"--epm-list: {entries.Count} endpoint(s)");
		}
	}

	private async Task<WmiClient> ConnectAsync(string host, CancellationToken cancellationToken)
	{
		var rpcParams = this.RpcParameters;

		// Ensure the resolver can find the host even when an IP is given.
		if (rpcParams.NetParameters.HostAddress is null || rpcParams.NetParameters.HostAddress.Length == 0)
			rpcParams.NetParameters.HostAddress = new[] { host };

		var remoteAddrs = await rpcParams.NetParameters.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
		if (remoteAddrs is null || remoteAddrs.Length == 0)
			throw new InvalidOperationException($"Unable to resolve host '{host}'");

		RpcClient rpcClient = this.Services.CreateRpcClient();
		rpcParams.ApplyTo(rpcClient, RpcAuthLevel.PacketIntegrity);

		if (!rpcParams.OfferNdr64.IsSpecified)
			rpcClient.OfferNdr64 = false; // NDR32 default: Titanis NDR64 DCOM fails on Server 2025+ (RPC 1783)

		DcomClient dcom = await DcomClient.ConnectTo(host, rpcClient, cancellationToken).ConfigureAwait(false);
		string workstation = rpcParams.Authentication.Workstation ?? string.Empty;
		int orpId = Random.Shared.Next(1024, 65535) & ~0x03;
		WmiClient wmi = await WmiClient.ConnectTo(workstation, orpId, dcom, cancellationToken).ConfigureAwait(false);

		// Touch root\cimv2 to validate access
		_ = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
		return wmi;
	}
}

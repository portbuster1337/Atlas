using System.ComponentModel;
using Titanis.Cli;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Msdcom;
using Titanis.Msrpc.Mswmi;

namespace Atlas.Protocols;

/// <summary>
/// NetExec-style WMI protocol host: authenticate against targets and optionally
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
	[Description("Working directory for the executed command")]
	public string? WorkingDir { get; set; }

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
		WmiClient wmi = await this.ConnectAsync(host, cancellationToken).ConfigureAwait(false);

		if (this.Exec is null)
		{
			AtlasConsole.Success($"{host}:{WmiPort}", "authenticated");
			return;
		}

		var ns = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
		var processClass = (WmiClassObject)await ns.GetObjectAsync("Win32_Process", cancellationToken).ConfigureAwait(false);

		string cmdLine = this.Exec;
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

		DcomClient dcom = await DcomClient.ConnectTo(host, rpcClient, cancellationToken).ConfigureAwait(false);
		string workstation = rpcParams.Authentication.Workstation ?? string.Empty;
		int orpId = Random.Shared.Next(1024, 65535) & ~0x03;
		WmiClient wmi = await WmiClient.ConnectTo(workstation, orpId, dcom, cancellationToken).ConfigureAwait(false);

		// Touch root\cimv2 to validate access
		_ = await wmi.OpenNamespace(WmiClient.RootCimV2Namespace, "en-US", cancellationToken).ConfigureAwait(false);
		return wmi;
	}
}

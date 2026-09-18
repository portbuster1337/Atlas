using Titanis;
using Titanis.DceRpc.Client;
using Titanis.Msrpc;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Msscmr;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;
using Titanis.Winterop.Registry;
using Titanis.Winterop.Security;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec wcc: Windows security configuration checks (registry/services/files/WMI subset).
/// </summary>
public sealed class SmbWccModule : AtlasModule<Smb2Client>
{
	public override string Name => "wcc";
	public override string Description => "Windows security configuration checks (UAC/LSA/RDP/Defender/LAPS/NetBIOS/...)";

	private sealed record CheckResult(string Name, string Status, string Detail);

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		var results = new List<CheckResult>();
		RpcClient rpc = ctx.Services.CreateRpcClient();
		using RemoteRegistryClient reg = new RemoteRegistryClient();
		try
		{
			await rpc.ConnectPipe(reg, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, reg.WellKnownPipeName ?? "winreg"), cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(wcc) Remote Registry unavailable: {ex.Message}");
			return;
		}
		RemoteRegistryClient regClient = reg;
		await using var lm = await regClient.OpenLocalMachine(RegistryAccessRights.KeyRead, cancellationToken).ConfigureAwait(false);

		async Task<object?> GetVal(string path, string name)
		{
			try
			{
				await using var k = await lm.OpenSubkey(path, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				var v = await k.GetValue(name, cancellationToken).ConfigureAwait(false);
				if (v.TypedValue is not null) return v.TypedValue;
				if (v.Bytes is not null)
				{
					if (v.Bytes.Length == 4) return BitConverter.ToUInt32(v.Bytes, 0);
					return System.Text.Encoding.Unicode.GetString(v.Bytes).TrimEnd('\0');
				}
			}
			catch { }
			return null;
		}

		static uint? ToU(object? o) => o switch
		{
			uint u => u, int i => (uint)i, long l => (uint)l, short s => (uint)s,
			string str when uint.TryParse(str.TrimEnd('\0'), out var p) => p,
			_ => null,
		};
		static string ToS(object? o) => o?.ToString()?.TrimEnd('\0') ?? "";

		async Task CheckDword(string name, string path, string value, Func<uint, bool> pass, string expect)
		{
			object? raw = await GetVal(path, value).ConfigureAwait(false);
			uint? v = ToU(raw);
			if (v is null) results.Add(new CheckResult(name, "N/A", $"{path}!{value} not set"));
			else if (pass(v.Value)) results.Add(new CheckResult(name, "OK", $"{value}={v}"));
			else results.Add(new CheckResult(name, "KO", $"{value}={v} (expected {expect})"));
		}

		await CheckDword("UAC enabled", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("Remote UAC filtering", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy", v => v == 0, "0").ConfigureAwait(false);
		await CheckDword("NoLMHash", @"System\CurrentControlSet\Control\Lsa", "NoLMHash", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("RunAsPPL", @"System\CurrentControlSet\Control\Lsa", "RunAsPPL", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("LsaCfgFlags (Credential Guard UEFI lock)", @"System\CurrentControlSet\Control\Lsa", "LsaCfgFlags", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("LmCompatibilityLevel >= 5", @"System\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", v => v >= 5, ">=5").ConfigureAwait(false);
		await CheckDword("WDigest disabled", @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", v => v == 0, "0").ConfigureAwait(false);
		await CheckDword("AlwaysInstallElevated HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", v => v == 0, "0").ConfigureAwait(false);
		await CheckDword("CachedLogonsCount <= 2", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", v => v <= 2, "<=2").ConfigureAwait(false);
		await CheckDword("SMB signing required", @"System\CurrentControlSet\Services\LanmanServer\Parameters", "requiresecuritysignature", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("SMB encryption", @"System\CurrentControlSet\Services\LanmanServer\Parameters", "EncryptData", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("LDAP signing (NTDS)", @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity", v => v == 2, "2").ConfigureAwait(false);
		await CheckDword("RDP NLA", @"System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("VBS enabled", @"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("LLMNR disabled", @"Software\policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", v => v == 0, "0").ConfigureAwait(false);
		await CheckDword("mDNS disabled", @"SYSTEM\CurrentControlSet\Services\DNScache\Parameters", "EnableMDNS", v => v == 0, "0").ConfigureAwait(false);
		await CheckDword("Defender TamperProtection", @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", v => v == 5, "5").ConfigureAwait(false);
		await CheckDword("Defender realtime", @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", v => v == 0, "0").ConfigureAwait(false);
		await CheckDword("FVE advanced startup", @"SOFTWARE\Policies\Microsoft\FVE", "UseAdvancedStartup", v => v == 1, "1").ConfigureAwait(false);
		await CheckDword("FVE TPM+PIN", @"SOFTWARE\Policies\Microsoft\FVE", "UseTPMPIN", v => v == 1, "1").ConfigureAwait(false);

		// PowerShell v2
		try
		{
			object? ps = await GetVal(@"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine", "PSCompatibleVersion").ConfigureAwait(false);
			string s = ToS(ps);
			results.Add(string.IsNullOrEmpty(s)
				? new CheckResult("PowerShell v2 absent", "N/A", "PSCompatibleVersion not set")
				: s.Contains("2.0") ? new CheckResult("PowerShell v2 absent", "KO", $"PSCompatibleVersion={s}") : new CheckResult("PowerShell v2 absent", "OK", $"PSCompatibleVersion={s}"));
		}
		catch { }

		// Defender exclusions present = KO
		foreach (var p in new[] { @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths", @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" })
		{
			try
			{
				await using var k = await lm.OpenSubkey(p, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
				var vals = new List<string>();
				await foreach (var v in k.GetValues(false, cancellationToken).ConfigureAwait(false)) vals.Add(v.Name);
				results.Add(vals.Count > 0
					? new CheckResult($"Defender exclusions ({p.Split('\\').Last()})", "KO", $"{vals.Count} exclusion(s): {string.Join(",", vals.Take(5))}")
					: new CheckResult($"Defender exclusions ({p.Split('\\').Last()})", "OK", "none"));
			}
			catch { results.Add(new CheckResult($"Defender exclusions ({p.Split('\\').Last()})", "N/A", "key absent")); }
		}

		// LAPS presence
		bool laps = false;
		foreach (var p in new[] { @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS", @"Software\Microsoft\Policies\LAPS" })
		{
			try { await using var k = await lm.OpenSubkey(p, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false); laps = true; } catch { }
		}
		results.Add(new CheckResult("LAPSv2 policy", laps ? "OK" : "N/A", laps ? "LAPS policy key present" : "no LAPS policy key"));

		// NetBIOS per-interface
		try
		{
			await using var ifaces = await lm.OpenSubkey(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces", RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
			await foreach (var sub in ifaces.GetSubkeyNames(cancellationToken).ConfigureAwait(false))
			{
				try
				{
					await using var k = await ifaces.OpenSubkey(sub.KeyName, RegistryAccessRights.KeyRead, RegistryKeyOptions.None, cancellationToken).ConfigureAwait(false);
					var v = await k.GetValue("NetbiosOptions", cancellationToken).ConfigureAwait(false);
					uint? nb = ToU(v.TypedValue ?? (object?)v.Bytes);
					results.Add(nb == 2
						? new CheckResult($"NetBIOS disabled ({sub.KeyName})", "OK", "NetbiosOptions=2")
						: new CheckResult($"NetBIOS disabled ({sub.KeyName})", nb is null ? "N/A" : "KO", $"NetbiosOptions={nb?.ToString() ?? "unset"} (2=disabled)"));
				}
				catch { }
			}
		}
		catch { }

		// Spooler service state via SCM
		try
		{
			RpcClient rpc2 = ctx.Services.CreateRpcClient();
			var scmClient = new Titanis.Msrpc.Msscmr.ScmClient();
			await rpc2.ConnectPipe(scmClient, ctx.Client, new UncPath(ctx.Host, Smb2Client.IpcName, scmClient.WellKnownPipeName ?? "svcctl"), cancellationToken).ConfigureAwait(false);
			using var scm = await scmClient.OpenScm(Titanis.Winterop.Security.ScmAccessRights.EnumerateService, cancellationToken).ConfigureAwait(false);
			var svcs = await scm.GetServicesAsync(cancellationToken).ConfigureAwait(false);
			var spooler = svcs.FirstOrDefault(s => s.ServiceName.Equals("Spooler", StringComparison.OrdinalIgnoreCase));
			results.Add(spooler is null
				? new CheckResult("Print Spooler", "N/A", "service not found")
				: new CheckResult("Print Spooler", spooler.State.ToString().Contains("Running") ? "KO" : "OK", $"state={spooler.State} (running=PrintNightmare surface)"));
		}
		catch (Exception ex) { results.Add(new CheckResult("Print Spooler", "N/A", ex.Message)); }

		// LAPS CSE files on C$
		try
		{
			bool lapsCse = false;
			foreach (var probe in new[] { @"Program Files\LAPS\CSE", @"Program Files\LAPS\CSE\AdmPwd.dll" })
			{
				try
				{
					await using var d = await ctx.Client.OpenDirectoryAsync(new UncPath(ctx.Host, "C$", probe), cancellationToken).ConfigureAwait(false);
					lapsCse = true;
				}
				catch { }
			}
			results.Add(new CheckResult("LAPS CSE files", lapsCse ? "OK" : "N/A", lapsCse ? @"C$\Program Files\LAPS\CSE present" : "absent"));
		}
		catch { }

		int ko = 0;
		foreach (var r in results)
		{
			if (r.Status == "KO")
			{
				ko++;
				AtlasConsole.Success($"{ctx.Host}:445", $"(wcc) KO: {r.Name} - {r.Detail}");
			}
			else
				AtlasConsole.Info($"{ctx.Host}:445", $"(wcc) {r.Status}: {r.Name} - {r.Detail}");
		}
		AtlasConsole.Info($"{ctx.Host}:445", $"(wcc) {ko} KO / {results.Count} checks");
	}
}

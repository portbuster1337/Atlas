using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec bitlocker: BitLocker volume status via WMI.
/// </summary>
public sealed class SmbBitlockerModule : AtlasModule<Smb2Client>
{
	public override string Name => "bitlocker";
	public override string Description => "Enumerates BitLocker volume protection status via WMI";

	private static readonly Dictionary<string, string> Methods = new(StringComparer.OrdinalIgnoreCase)
	{
		["0"] = "None", ["1"] = "AES_128_WITH_DIFFUSER", ["2"] = "AES_256_WITH_DIFFUSER",
		["3"] = "AES_128", ["4"] = "AES_256", ["5"] = "HARDWARE_ENCRYPTION",
		["6"] = "XTS_AES_128", ["7"] = "XTS_AES_256",
	};

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		try
		{
			List<Dictionary<string, object?>> rows;
			try
			{
				rows = await SmbWmiHelper.QueryAsync(ctx, @"root\CIMv2\Security\MicrosoftVolumeEncryption",
					"SELECT DriveLetter, ProtectionStatus, EncryptionMethod FROM Win32_EncryptableVolume", cancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex) when (ex.Message.Contains("INVALID_NAMESPACE", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("0x8004100E"))
			{
				AtlasConsole.Info($"{ctx.Host}:445", "(bitlocker) BitLocker WMI namespace not found");
				return;
			}
			foreach (var row in rows)
			{
				row.TryGetValue("DriveLetter", out var drive);
				row.TryGetValue("ProtectionStatus", out var prot);
				row.TryGetValue("EncryptionMethod", out var method);
				string protText = (prot?.ToString() == "1") ? "ENABLED" : "disabled";
				string methText = Methods.TryGetValue(method?.ToString() ?? "", out var m) ? m : (method?.ToString() ?? "?");
				if (prot?.ToString() == "1")
					AtlasConsole.Success($"{ctx.Host}:445", $"(bitlocker) {drive}: {protText} ({methText})");
				else
					AtlasConsole.Info($"{ctx.Host}:445", $"(bitlocker) {drive}: {protText} ({methText})");
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(bitlocker) {rows.Count} volume(s)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(bitlocker) Failed: {ex.Message}");
		}
	}
}

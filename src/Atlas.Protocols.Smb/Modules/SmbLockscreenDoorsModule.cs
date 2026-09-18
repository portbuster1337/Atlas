using Titanis;
using Titanis.Smb2;

namespace Atlas.Protocols.Smb.Modules;

/// <summary>
/// NetExec lockscreendoors: flags backdoored accessibility binaries via FileDescription.
/// </summary>
public sealed class SmbLockscreenDoorsModule : AtlasModule<Smb2Client>
{
	public override string Name => "lockscreendoors";
	public override string Description => "Detects backdoored accessibility binaries (utilman/sethc/...) via FileDescription";

	private static readonly string[] Binaries = new[]
	{
		"utilman.exe", "narrator.exe", "sethc.exe", "osk.exe", "magnify.exe",
		"EaseOfAccessDialog.exe", "voiceaccess.exe", "displayswitch.exe", "atbroker.exe",
	};

	private static readonly Dictionary<string, string> Expected = new(StringComparer.OrdinalIgnoreCase)
	{
		["utilman.exe"] = "Utility Manager",
		["narrator.exe"] = "Screen Reader",
		["sethc.exe"] = "Accessibility shortcut keys",
		["osk.exe"] = "Accessibility On-Screen Keyboard",
		["magnify.exe"] = "Microsoft Screen Magnifier",
		["easeofaccessdialog.exe"] = "Ease of Access Dialog Host",
		["voiceaccess.exe"] = "Voice access",
		["displayswitch.exe"] = "Display Switch",
		["atbroker.exe"] = "Windows Assistive Technology Manager",
	};

	public override async Task RunAsync(AtlasModuleContext<Smb2Client> ctx, CancellationToken cancellationToken)
	{
		int backdoors = 0;
		try
		{
			foreach (var bin in Binaries)
			{
				cancellationToken.ThrowIfCancellationRequested();
				byte[] data;
				try
				{
					await using var stream = await ctx.Client.OpenFileReadAsync(new UncPath(ctx.Host, "C$", $"Windows\\System32\\{bin}"), cancellationToken).ConfigureAwait(false);
					using var ms = new MemoryStream();
					await stream.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
					data = ms.ToArray();
				}
				catch (Exception ex)
				{
					AtlasConsole.Warn($"{ctx.Host}:445", $"(lockscreendoors) cannot read {bin}: {ex.Message}");
					continue;
				}
				string tmp = Path.Combine(Path.GetTempPath(), $"atlas_{Guid.NewGuid():N}_{bin}");
				try
				{
					await File.WriteAllBytesAsync(tmp, data, cancellationToken).ConfigureAwait(false);
					string desc = string.Empty;
					try
					{
						var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(tmp);
						desc = vi.FileDescription ?? string.Empty;
					}
					catch { }
					if (desc.Contains("Command Processor", StringComparison.OrdinalIgnoreCase) ||
						desc.Contains("PowerShell", StringComparison.OrdinalIgnoreCase))
					{
						backdoors++;
						AtlasConsole.Success($"{ctx.Host}:445", $"(lockscreendoors) BACKDOOR: {bin} -> FileDescription='{desc}'");
					}
					else if (Expected.TryGetValue(bin, out var exp) && !desc.StartsWith(exp.Split(',')[0], StringComparison.OrdinalIgnoreCase))
					{
						AtlasConsole.Warn($"{ctx.Host}:445", $"(lockscreendoors) SUSPICIOUS: {bin} -> FileDescription='{desc}' (expected '{exp}')");
					}
					else
					{
						AtlasConsole.Info($"{ctx.Host}:445", $"(lockscreendoors) {bin}: '{desc}' OK");
					}
				}
				finally
				{
					try { File.Delete(tmp); } catch { }
				}
			}
			AtlasConsole.Info($"{ctx.Host}:445", $"(lockscreendoors) {backdoors} backdoor(s)");
		}
		catch (Exception ex)
		{
			AtlasConsole.Fail($"{ctx.Host}:445", $"(lockscreendoors) Failed: {ex.Message}");
		}
	}
}

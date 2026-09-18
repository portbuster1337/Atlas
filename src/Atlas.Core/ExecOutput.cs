using Titanis;
using Titanis.Smb2;

namespace Atlas;

/// <summary>
/// NetExec-style exec output retrieval: the command is redirected to a
/// random file on the target, which is then read back over SMB and
/// deleted. Returns null when unavailable (non-admin, timeout) so
/// callers can fall back to PID-only output.
/// </summary>
public static class ExecOutput
{
	public static string NewStageFile()
	{
		const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		Span<char> buf = stackalloc char[6];
		for (int i = 0; i < buf.Length; i++)
			buf[i] = chars[Random.Shared.Next(chars.Length)];
		return new string(buf) + ".tmp";
	}

	/// <summary>
	/// Local path the target writes to (no loopback SMB session needed).
	/// C:\ root: proven reliable on hardened DCs; read back via C$.
	/// </summary>
	public static string LocalPath(string stageFile) => $"C:\\{stageFile}";

	/// <summary>
	/// C$-relative path used to read the staged file back.
	/// </summary>
	public static string RemotePath(string stageFile) => stageFile;

	/// <summary>
	/// Builds a CMD line in NetExec wmiexec form (no inner quotes).
	/// </summary>
	public static string WrapCmd(string cmd, string? stageFile)
		=> (stageFile is null)
			? $"cmd.exe /Q /c {cmd}"
			: $"cmd.exe /Q /c {cmd} 1> {LocalPath(stageFile)} 2>&1";

	/// <summary>
	/// Builds a CMD line for SCM services (quoted inner command, proven
	/// reliable for service launches).
	/// </summary>
	public static string WrapCmdService(string cmd, string? stageFile)
		=> (stageFile is null)
			? $"cmd.exe /Q /c \"{cmd}\""
			: $"cmd.exe /Q /c \"{cmd} 1> {LocalPath(stageFile)} 2>&1\"";

	/// <summary>
	/// Builds a PowerShell line; redirect uses PowerShell's own operator.
	/// </summary>
	public static string WrapPs(string cmd, string? stageFile)
	{
		string inner = cmd.Replace("\"", "\\\"");
		return (stageFile is null)
			? $"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"{inner}\""
			: $"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"{inner} 1> {LocalPath(stageFile)} 2>&1\"";
	}

	public static async Task<string?> ReadAsync(Smb2Client smb, string host, string stageFile, CancellationToken ct)
	{
		string rel = RemotePath(stageFile);
		// Open with ReadWrite sharing: the writer still holds the file while
		// the command runs; FileShare.Read (OpenFileReadAsync default) would
		// conflict with its write handle (STATUS_SHARING_VIOLATION).
		async Task<Smb2FileStream> OpenSharedAsync()
		{
			var share = await smb.GetShare(new UncPath(host, "C$", string.Empty), ct).ConfigureAwait(false);
			return await share.CreateFileAsync(rel, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, ct).ConfigureAwait(false);
		}
		async Task DeleteAsync()
		{
			// Retry: the writer may still be exiting and holding the file.
			for (int i = 0; i < 5; i++)
			{
				try { await smb.DeleteFileAsync(new UncPath(host, "C$", rel), CancellationToken.None).ConfigureAwait(false); return; }
				catch { await Task.Delay(500, CancellationToken.None).ConfigureAwait(false); }
			}
		}
		try
		{
			// Poll for completion: NetExec-style, size-stable read.
			long lastSize = -1;
			for (int i = 0; i < 40; i++)
			{
				ct.ThrowIfCancellationRequested();
				try
				{
					await using var probe = await OpenSharedAsync().ConfigureAwait(false);
					using var ms = new MemoryStream();
					await probe.CopyToAsync(ms, ct).ConfigureAwait(false);
					long size = ms.Length;
					if (size > 0 && size == lastSize)
					{
						await DeleteAsync().ConfigureAwait(false);
						return Decode(ms.ToArray());
					}
					lastSize = size;
				}
				catch
				{
					// Not there yet.
				}
				await Task.Delay(500, ct).ConfigureAwait(false);
			}
			// Timeout: best-effort final read, then try to remove the staged file.
			try
			{
				await using var stream = await OpenSharedAsync().ConfigureAwait(false);
				using var ms = new MemoryStream();
				await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
				await DeleteAsync().ConfigureAwait(false);
				string text = Decode(ms.ToArray());
				return text.Length > 0 ? text : null;
			}
			catch
			{
				await DeleteAsync().ConfigureAwait(false);
				return null;
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch
		{
			return null;
		}
	}

	/// <summary>
	/// Decodes command output: UTF-16LE (PowerShell redirect, optional BOM)
	/// or UTF-8/OEM bytes otherwise. Invariant-safe (no code pages).
	/// </summary>
	private static string Decode(byte[] data)
	{
		if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
			return System.Text.Encoding.Unicode.GetString(data, 2, data.Length - 2).TrimEnd().TrimEnd('\0');
		if (data.Length >= 4)
		{
			int nulOdd = 0, checks = 0;
			for (int i = 1; i < data.Length && i < 64; i += 2) { checks++; if (data[i] == 0) nulOdd++; }
			if (checks > 0 && nulOdd == checks)
				return System.Text.Encoding.Unicode.GetString(data).TrimEnd().TrimEnd('\0');
		}
		return System.Text.Encoding.UTF8.GetString(data).TrimEnd().TrimEnd('\0');
	}
}

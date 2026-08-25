using System.Text;

namespace Atlas;

/// <summary>
/// NetExec-style console output: <c>[HH:mm:ss] [sev] host - message</c>.
/// </summary>
public static class AtlasConsole
{
	private const string Reset = "\x1b[0m";
	private const string Green = "\x1b[32m";
	private const string Red = "\x1b[31m";
	private const string Yellow = "\x1b[33m";
	private const string Blue = "\x1b[34m";
	private const string Cyan = "\x1b[36m";

	private static readonly object _sync = new();

	static AtlasConsole()
	{
		if (OperatingSystem.IsWindows())
		{
			try
			{
				_ = Console.OutputEncoding;
			}
			catch { }
		}
	}

	public static void Success(string host, string msg) => Write('+', Green, host, msg);
	public static void Info(string host, string msg) => Write('*', Blue, host, msg);
	public static void Fail(string host, string msg) => Write('-', Red, host, msg);
	public static void Warn(string host, string msg) => Write('!', Yellow, host, msg);

	public static void Line(string msg)
	{
		lock (_sync)
		{
			Console.WriteLine($"{DateTime.Now:HH:mm:ss} {msg}");
		}
	}

	private static void Write(char severity, string color, string host, string msg)
	{
		var sb = new StringBuilder();
		sb.Append(DateTime.Now.ToString("HH:mm:ss"));
		sb.Append(' ').Append('[').Append(color).Append(severity).Append(Reset).Append("] ");
		sb.Append(Cyan).Append(host).Append(Reset).Append(" - ").Append(msg);
		lock (_sync)
		{
			Console.WriteLine(sb.ToString());
		}
	}
}

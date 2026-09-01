using System.Net;

namespace Atlas;

/// <summary>
/// single host/IP, CIDR, last-octet or full-IP ranges, comma lists, and <c>@file</c> references.
/// </summary>
public static class TargetList
{
	private const int MaxTargets = 65536;

	public static List<string> Parse(string spec)
	{
		ArgumentNullException.ThrowIfNull(spec);

		var results = new List<string>();
		foreach (var rawEntry in spec.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
		{
			var entry = rawEntry;
			if (entry.StartsWith('@'))
			{
				var path = entry[1..];
				if (!File.Exists(path))
					throw new FileNotFoundException($"Target file not found: {path}");
				foreach (var line in File.ReadLines(path))
				{
					var trimmed = line.Trim();
					if (trimmed.Length == 0 || trimmed.StartsWith('#'))
						continue;
					AddEntry(results, trimmed);
					if (results.Count > MaxTargets)
						throw new InvalidOperationException($"Too many targets (limit {MaxTargets}).");
				}
			}
			else
			{
				AddEntry(results, entry);
			}

			if (results.Count > MaxTargets)
				throw new InvalidOperationException($"Too many targets (limit {MaxTargets}).");
		}

		return results;
	}

	private static string UIntToAddress(uint v)
		=> new IPAddress(new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }).ToString();

	private static void AddEntry(List<string> results, string entry)
	{
		if (entry.Length == 0)
			return;

		// CIDR: a.b.c.d/nn
		int slash = entry.IndexOf('/');
		if (slash > 0 && IPAddress.TryParse(entry[..slash], out var cidrAddr) && int.TryParse(entry[(slash + 1)..], out int prefix) && prefix is >= 0 and <= 32)
		{
			AddCidr(results, cidrAddr, prefix);
			return;
		}

		// Range: a.b.c.d-e (last octet) or a.b.c.d-a.b.c.e (full IPs)
		int dash = LastRangeDash(entry);
		if (dash > 0)
		{
			var left = entry[..dash].Trim();
			var right = entry[(dash + 1)..].Trim();
			if (TryParseRange(left, right, out var start, out var end))
			{
				for (uint v = start; v <= end; v++)
				{
					results.Add(UIntToAddress(v));
					if (results.Count > MaxTargets)
						throw new InvalidOperationException($"Too many targets (limit {MaxTargets}).");
				}
				return;
			}
		}

		// Literal host name or IP
		results.Add(entry);
	}

	private static int LastRangeDash(string entry)
	{
		// Avoid treating hostnames with dashes as ranges; require digits around the dash.
		for (int i = entry.Length - 2; i > 0; i--)
		{
			if (entry[i] == '-' && char.IsDigit(entry[i - 1]) && char.IsDigit(entry[i + 1]))
				return i;
		}
		return -1;
	}

	private static bool TryParseRange(string left, string right, out uint start, out uint end)
	{
		start = end = 0;
		if (!Ipv4ToUInt(left, out start))
			return false;

		// Only treat the right side as a full IP when it contains a dot;
		// IPAddress.TryParse accepts bare integers like "3" as 0.0.0.3.
		if (right.Contains('.'))
		{
			if (!Ipv4ToUInt(right, out end))
				return false;
			return end >= start;
		}

		// Right side may be a bare final octet sharing the left /24
		if (int.TryParse(right, out int lastOctet) && lastOctet is >= 0 and <= 255)
		{
			uint baseValue = start & 0xFFFFFF00;
			end = baseValue | (uint)lastOctet;
			if (end < start)
				(end, start) = (start, end);
			return true;
		}

		return false;
	}

	private static bool Ipv4ToUInt(string text, out uint value)
	{
		value = 0;
		if (!IPAddress.TryParse(text, out var addr))
			return false;
		if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
			return false;
		var bytes = addr.GetAddressBytes();
		value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
		return true;
	}

	private static void AddCidr(List<string> results, IPAddress addr, int prefix)
	{
		if (!Ipv4ToUInt(addr.ToString(), out uint network))
			return;

		if (prefix == 0)
		{
			throw new ArgumentOutOfRangeException(nameof(prefix), "A /0 target range is not supported.");
		}

		uint mask = prefix >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1);
		uint netBase = network & mask;
		uint broadcast = netBase | ~mask;
		uint first = (prefix <= 30) ? netBase + 1 : netBase;
		uint last = (prefix <= 30) ? broadcast - 1 : broadcast;

		for (uint v = first; v <= last; v++)
		{
			results.Add(UIntToAddress(v));
			if (results.Count > MaxTargets)
				throw new InvalidOperationException($"Too many targets (limit {MaxTargets}).");
		}
	}
}

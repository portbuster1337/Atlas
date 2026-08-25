using System.Reflection;

namespace Atlas;

/// <summary>
/// Context handed to a module for one target host.
/// </summary>
public sealed class AtlasModuleContext<TClient>
{
	public required string Host { get; init; }
	public required TClient Client { get; init; }
	public required IServiceProvider Services { get; init; }
	/// <summary>Options parsed from <c>-o key=value,key2=value2</c>.</summary>
	public IReadOnlyDictionary<string, string> Options { get; init; } =
		new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

	public string Option(string key, string? fallback = null)
		=> this.Options.TryGetValue(key, out var v) ? v : (fallback ?? string.Empty);
}

/// <summary>
/// A protocol module. Derive from this with the protocol's connected client type
/// (e.g. <see cref="Titanis.Smb2.Smb2Client"/>) and it is auto-discovered.
/// </summary>
public abstract class AtlasModule<TClient>
{
	public abstract string Name { get; }
	public abstract string Description { get; }

	public abstract Task RunAsync(AtlasModuleContext<TClient> context, CancellationToken cancellationToken);
}

public static class AtlasModuleRegistry
{
	private static readonly object _sync = new();
	private static List<(Type implType, Type clientType)>? _cache;

	private static void EnsureCache()
	{
		if (_cache is not null)
			return;

		var found = new List<(Type, Type)>();
		foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
		{
			if (asm.IsDynamic)
				continue;
			var name = asm.GetName().Name ?? string.Empty;
			if (!name.StartsWith("Atlas", StringComparison.Ordinal))
				continue;

			Type[] types;
			try { types = asm.GetTypes(); }
			catch (ReflectionTypeLoadException ex) { types = ex.Types.Where(t => t is not null).ToArray()!; }

			foreach (var t in types)
			{
				var clientType = GetModuleClientType(t);
				if (clientType is not null)
					found.Add((t, clientType));
			}
		}
		lock (_sync) { _cache = found; }
	}

	private static Type? GetModuleClientType(Type? type)
	{
		for (var t = type; t is not null; t = t.BaseType)
		{
			if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(AtlasModule<>))
				return t.GetGenericArguments()[0];
		}
		return null;
	}

	/// <summary>Instantiates all discovered modules bound to the given client type.</summary>
	public static IEnumerable<AtlasModule<TClient>> Discover<TClient>()
	{
		EnsureCache();
		foreach (var (implType, clientType) in _cache!)
		{
			if (clientType == typeof(TClient))
				yield return (AtlasModule<TClient>)Activator.CreateInstance(implType)!;
		}
	}

	/// <summary>Selects discovered modules by name (case-insensitive).</summary>
	public static IEnumerable<AtlasModule<TClient>> Select<TClient>(IEnumerable<string> names)
	{
		var wanted = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
		foreach (var mod in Discover<TClient>())
		{
			if (wanted.Contains(mod.Name))
				yield return mod;
		}
	}

	public static IReadOnlyDictionary<string, string> ParseOptionString(string? spec)
	{
		var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		if (string.IsNullOrWhiteSpace(spec))
			return dict;
		foreach (var pair in spec.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
		{
			int eq = pair.IndexOf('=');
			if (eq <= 0)
				throw new FormatException($"Module options must be key=value pairs separated by commas. Invalid: '{pair}'");
			dict[pair[..eq].Trim()] = pair[(eq + 1)..].Trim();
		}
		return dict;
	}
}

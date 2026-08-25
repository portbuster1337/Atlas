using System.ComponentModel;
using Atlas.Protocols;
using Titanis.Cli;

namespace Atlas;

[Description("Atlas - network execution toolkit built on Titanis")]
[Subcommand("smb", typeof(SmbCommand))]
[Subcommand("wmi", typeof(WmiCommand))]
[Subcommand("ldap", typeof(LdapCommand))]
[Subcommand("dcsync", typeof(DcsyncCommand))]
[Subcommand("kerberos", typeof(KerberosCommand))]
internal sealed partial class Program : MultiCommand
{
	static int Main(string[] args)
		=> RunProgramAsync<Program>(NormalizeArgs(args));

	/// <summary>
	/// Rewrites <c>--flag</c> to <c>-flag</c> so NetExec-style double-dash
	/// parameters work alongside Titanis's single-dash syntax.
	/// </summary>
	internal static string[] NormalizeArgs(string[] args)
		=> args.Select(a => (a.Length > 2 && a.StartsWith("--")) ? a[1..] : a).ToArray();
}

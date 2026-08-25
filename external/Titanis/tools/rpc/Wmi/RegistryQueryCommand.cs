using System.ComponentModel;
using Titanis.Cli;
using Titanis.Cli.Registry;
using Titanis.Winterop.Registry;


namespace Wmi.Registry
{
	/// <task category="WMI;Registry;Enumeration">List the contents of a registry key</task>
	/// <task category="WMI;Registry;Enumeration">Search for specific registry keys, values, or data</task>
	[Command]
	[OutputRecordType(typeof(RegistryItem))]
	[OutputFieldFormat(nameof(RegistryItem.Name), RegistryItemNameFormatter.DefaultIfEmptyFormat, typeof(RegistryItemNameFormatter))]
	[Description("Query registry values")]
	[Example(@"Query all values and direct subkeys of HKLM\Software\MyApp", @"{0} -UserName milchick -Password Br3@kr00m! LUMON-FS1 HKLM\Software\MyApp")]
	[Example(@"Query the value names 'InstallPath' and 'Version' under HKLM\Software\MyApp", @"{0} -UserName milchick -Password Br3@kr00m! LUMON-FS1 HKLM\Software\MyApp -ValueNameFilter InstallPath, Version")]
	[Example(@"Finds all non-empty default value under HKLM\Software\Microsoft", @"{0} -UserName milchick -Password Br3@kr00m! LUMON-FS1 HKLM\Software\Microsoft -QueryDefaultValue -Recursive ")]
	[Example(@"Search for any value name or data item containing the string 'password' or 'credential' under HKLM\Software", @"{0} -UserName milchick -Password Br3@kr00m! LUMON-FS1 HKLM\Software -ValueSearch -DataSearch -SearchPatterns password, credential -Recursive")]
	internal class RegistryQueryCommand : RegistryQueryCommandBase
	{
		protected override void OnKeyMatch(RegistryPath keyPath) => this.WriteRecord(new RegistryItem(keyPath));

		protected override void OnValueMatch(RegistryPath keyPath, RegistryValueInfo value) => this.WriteRecord(new RegistryItem(keyPath.KeyPath, value));
	}
}

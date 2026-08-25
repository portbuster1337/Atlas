using Titanis.Cli;
using Titanis.Winterop.Registry;
using Titanis.Cli.Registry;

namespace Wmi.Registry
{
	/// <summary>
	/// Implements registry query functionality based off the semantics of reg.exe
	/// </summary>
	//[DetailedHelpResource(typeof(Messages), nameof(Messages.wmi_base_query_Detailed))]
	[OutputRecordType(typeof(RegistryItem))]
	internal abstract partial class RegistryQueryCommandBase : WmiRegistryCommandBase, IRegistrySearchCallback
	{
		[ParameterGroup(ParameterGroupOptions.AlwaysInstantiate)]
		public RegistryQueryParameters QueryParameters { get; set; }


		//TODO: WMI StdRegProv GetSecurityDescriptor does not currently work as expected.
		//[Parameter]
		//[Description("Queries key security descriptors")]
		//[Alias("sec")]
		//public SwitchParam GetSecurity { get; set; }

		/// <summary>
		/// Called before the query begins.
		/// </summary>
		protected virtual void OnBeforeQuery()
		{
		}
		/// <summary>
		/// Called after the query has completed.
		/// </summary>
		protected virtual void OnQueryComplete()
		{
			//No-op
		}

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
		private RegistrySearchFilter _filter;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.


		protected override void ValidateParameters(ParameterValidationContext context)
		{
			base.ValidateParameters(context);

			this._filter = this.QueryParameters.ValidateAndBuildFilter(context);

		}


		//If the value is specified, we are querying a specific value
		//If a value is not specified We print all values under the key, and all keys under the key.
		//Type filter applies in all cases when specified (we will return none if the type doesn't match a specific value specified)
		protected override async Task<int> RunAsync(dynamic registry, CancellationToken cancellationToken)
		{
			object objreg = registry; //dynamics shouldn't be passed into function calls if we can avoid it for performance reasons.
			this.OnBeforeQuery();

			var searcher = new RegistrySearcher(this, this._filter!, this.Log);
			await searcher.DoSearch(new WmiRegistryKey(objreg, this.keyPath, this.Log), cancellationToken);

			OnQueryComplete();
			return 0;


		}


		protected abstract void OnKeyMatch(RegistryPath keyPath);

		void IRegistrySearchCallback.OnKeyMatch(RegistryPath keyPath) => this.OnKeyMatch(keyPath);

		protected abstract void OnValueMatch(RegistryPath keyPath, RegistryValueInfo value);
		void IRegistrySearchCallback.OnValueMatch(RegistryPath keyPath, RegistryValueInfo value) => this.OnValueMatch(keyPath, value);
	}
}

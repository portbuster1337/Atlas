namespace Titanis.Asn1.Metadata
{
	/// <summary>
	/// Describes a range of 64-bit values.
	/// </summary>
	public struct Asn1Int64Range
	{
		public Asn1Int64Range(long? min, bool includesMin, long? max, bool includesMax)
		{
			this.Min = min;
			this.IncludesMin = includesMin;
			this.Max = max;
			this.IncludesMax = includesMax;
		}
		public Asn1Int64Range(long? value)
		{
			this.Min = value;
			this.IncludesMin = true;
			this.Max = value;
			this.IncludesMax = true;
		}

		/// <inheritdoc/>
		public override string ToString()
			=> $"{(this.Min.HasValue ? this.Min.Value : "MIN")}{(this.IncludesMin ? null : "<")}..{(this.IncludesMax ? null : "<")}{(this.Max.HasValue ? this.Max.Value : "MAX")}";

		public bool IsClosed => this.Min.HasValue && this.Max.HasValue;
		public bool IsOpen => !this.IsClosed;

		/// <summary>
		/// Gets the minimum value of the range.
		/// </summary>
		public long? Min { get; private set; }
		/// <summary>
		/// Gets a value indicating whether the range includes the minimum value.
		/// </summary>
		public bool IncludesMin { get; }

		/// <summary>
		/// Gets the maximum value of the range.
		/// </summary>
		public long? Max { get; private set; }
		/// <summary>
		/// Gets a value indicating whether the range includes the maximum value.
		/// </summary>
		public bool IncludesMax { get; }
	}
}
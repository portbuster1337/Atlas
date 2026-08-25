using System;
using System.Collections.Generic;
using System.Text;

namespace Titanis.Asn1.Metadata
{
	public sealed class Asn1NamedBit
	{
		public Asn1NamedBit(string name, int position)
		{
			if (string.IsNullOrEmpty(name))
				throw new ArgumentNullException(nameof(name));

			this.Name = name;
			this.Position = position;
		}

		/// <inheritdoc/>
		public sealed override string ToString() => $"{this.Name}({this.Position})";

		public string Name { get; }
		public int Position { get; }
	}
}

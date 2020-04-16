using Newtonsoft.Json;
using System;

namespace com.tmobile.oss.security.taap.jwe
{
	/// <summary>
	/// Encapsulates an encrypted value.
	/// </summary>
	public class SecureString : IDisposable
	{
		private string encryptedValue;

		public SecureString(string encryptedValue)
		{
			this.encryptedValue = encryptedValue;
		}

		[JsonIgnore]
		public string Value
		{
			get
			{
				return this.encryptedValue;
			}
		}

		/// <summary>
		/// Returns a string object representing a masked value.  
		/// Encrypted data is very large and obscure so direct output 
		/// is meaningless and makes logs difficult to read. 
		/// </summary>
		[JsonProperty("Value")]
		public string ValueMasked
		{
			get
			{
				return ToString();
			}
		}

		/// <summary>
		/// Returns a string object representing a masked value.  
		/// Encrypted data is very large and obscure so direct output 
		/// is meaningless and makes logs difficult to read. 
		/// </summary>
		public override string ToString()
		{
			return "******";
		}

		#region IDisposable Support
		private bool disposedValue = false;

		void Dispose(bool disposing)
		{
			if (!disposedValue)
			{
				if (disposing)
				{
					this.encryptedValue = null;
				}

				disposedValue = true;
			}
		}

		// This code added to correctly implement the disposable pattern.
		public void Dispose()
		{
			Dispose(true);
		}
		#endregion
	}
}

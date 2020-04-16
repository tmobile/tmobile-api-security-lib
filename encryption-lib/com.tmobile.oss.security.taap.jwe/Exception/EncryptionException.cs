using System;

namespace com.tmobile.oss.security.taap.jwe
{
	public class EncryptionException : Exception
	{
		public EncryptionException(string message) : base(message)
		{
		}

		public EncryptionException(string message, Exception e) : base(message, e)
		{
		}
	}
}

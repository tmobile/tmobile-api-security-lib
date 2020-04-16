
namespace com.tmobile.oss.security.taap.jwe
{
	public class InvalidHeaderException : EncryptionException
	{
		public InvalidHeaderException(string message) : base(message)
		{
		}
	}
}

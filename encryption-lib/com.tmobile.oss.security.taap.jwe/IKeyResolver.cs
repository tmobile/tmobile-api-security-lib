using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
	public interface IKeyResolver
	{
		Task<JsonWebKey> GetEncryptionKeyAsync();

		Task<JsonWebKey> GetDecryptionKeyAsync(string kid);
	}
}
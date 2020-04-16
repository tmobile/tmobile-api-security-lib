using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
    public interface IEncryption
    {
        Task<string> EncryptAsync(string value);
        Task<string> DecryptAsync(string cipher);
    }
}
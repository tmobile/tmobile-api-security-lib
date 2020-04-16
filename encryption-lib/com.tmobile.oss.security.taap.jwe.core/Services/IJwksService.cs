using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
    public interface IJwksService
    {
        Task<List<JsonWebKey>> GetJsonWebKeyListAsync();
    }
}
using System;
using System.Threading.Tasks;
using System.Web.Http;
using com.tmobile.oss.security.taap.jwe;
using Newtonsoft.Json;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2.Models
{
    public class JwksController : ApiController
    {
        [HttpGet]
        public async Task<Jwks> GetJsonWebKeyListAsync()
        {
            var privateRsaJson = System.IO.File.ReadAllText(AppDomain.CurrentDomain.RelativeSearchPath + @"\TestData\JwksRSAPublic.json");
            var privateRsaJsonWebKey = JsonConvert.DeserializeObject<Jwks>(privateRsaJson);
            return await Task.FromResult(privateRsaJsonWebKey);
        }
    }
}
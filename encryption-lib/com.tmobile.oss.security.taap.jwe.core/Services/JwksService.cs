using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("com.tmobile.oss.security.taap.jwe.test")]
namespace com.tmobile.oss.security.taap.jwe
{
    /// <summary>
    /// Jwks Service for DoNotSellSettings 
    ///     /jwks/v1/qlab02/chubccpadonotsellsetting
    /// </summary>
    internal class JwksService : IJwksService
    {
        private readonly HttpClient httpClient;
        private readonly Uri jwkUrl;

        /// <summary>
        /// Custom constructor
        /// </summary>
        /// <param name="httpClient">Http Client</param>
        /// <param name="jwkUrl">JWK Server URL</param>
        public JwksService(HttpClient httpClient, string jwkUrl)
        {
            this.httpClient = httpClient;
            this.jwkUrl = new Uri(jwkUrl);
        }

        /// <summary>
        /// Get JsonWebKey List Async
        /// </summary>
        /// <returns>List JsonWebKey</returns>
        public async Task<List<JsonWebKey>> GetJsonWebKeyListAsync()
        {
            var jsonWebKeyList = new List<JsonWebKey>();

            using (var httpClient = this.httpClient)
            {
                httpClient.Timeout = TimeSpan.FromSeconds(30);
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                httpClient.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
                httpClient.BaseAddress = new Uri($"{this.jwkUrl.Scheme}://{this.jwkUrl.Host}");

                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, this.jwkUrl.PathAndQuery);
                using (var httpResponseMessage = await httpClient.SendAsync(httpRequestMessage))
                {
                    if (httpResponseMessage.IsSuccessStatusCode)
                    {
                        var json = await httpResponseMessage.Content.ReadAsStringAsync();
                        var jwks = JsonConvert.DeserializeObject<Jwks>(json);
                        jsonWebKeyList.AddRange(jwks.Keys);
                    }
                }
            }
            
            return jsonWebKeyList;
        }
    }
}

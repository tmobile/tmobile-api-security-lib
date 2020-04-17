/*
 * Copyright 2020 T-Mobile US, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
    /// <summary>
    /// Jwks Service
    /// </summary>
    public class JwksService : IJwksService
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
            this.jwkUrl = new Uri(jwkUrl);

            this.httpClient = httpClient;
            httpClient.Timeout = TimeSpan.FromSeconds(30);
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
            httpClient.BaseAddress = new Uri($"{this.jwkUrl.Scheme}://{this.jwkUrl.Host}");
        }

        /// <summary>
        /// Get JsonWebKey List Async
        /// </summary>
        /// <returns>List JsonWebKey</returns>
        public async Task<List<JsonWebKey>> GetJsonWebKeyListAsync()
        {
            var jsonWebKeyList = new List<JsonWebKey>();

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, this.jwkUrl.PathAndQuery);
            var httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                var json = await httpResponseMessage.Content.ReadAsStringAsync();
                var jwks = JsonConvert.DeserializeObject<Jwks>(json);
                jsonWebKeyList.AddRange(jwks.Keys);
            }

            return jsonWebKeyList;
        }
    }
}

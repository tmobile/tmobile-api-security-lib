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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe.test
{
	[TestClass]
	public class KeyResolverTest
	{
		private List<JsonWebKey> privateJsonWebKeyList;
		private Mock<JwksService> publicRsaJwksService;
		private Mock<JwksService> publicEcJwksService;
		private Mock<JwksService> publicOctJwksService;
		private long cacheDurationSeconds;

		[TestInitialize]
		public void TestInitialize()
		{
			var httpClient = new HttpClient();
			var jwkUrl = "http://somedomain.com/somepath";
			this.cacheDurationSeconds = 3600;

			// Public RSA Jwks
			var publicRsaJwksJson = File.ReadAllText(@"TestData\JwksRSAPublic.json")
										.Replace(Environment.NewLine, string.Empty);
			var publicRsaJwks = JsonConvert.DeserializeObject<Jwks>(publicRsaJwksJson);
			var publicRsaJsoneWebKeyList = new List<JsonWebKey>();
			publicRsaJsoneWebKeyList.AddRange(publicRsaJwks.Keys);
			this.publicRsaJwksService = new Mock<JwksService>(httpClient, jwkUrl);
			this.publicRsaJwksService.Setup<Task<List<JsonWebKey>>>(s => s.GetJsonWebKeyListAsync())
									 .Returns(Task.FromResult(publicRsaJsoneWebKeyList));

			// Public EC Jwks
			var publicEcJwksJson = File.ReadAllText(@"TestData\JwksECPublic.json")
									   .Replace(Environment.NewLine, string.Empty);
			var publicEcJwks = JsonConvert.DeserializeObject<Jwks>(publicEcJwksJson);
			var publicEcJsoneWebKeyList = new List<JsonWebKey>(publicEcJwks.Keys);
			this.publicEcJwksService = new Mock<JwksService>(httpClient, jwkUrl);
			this.publicEcJwksService.Setup<Task<List<JsonWebKey>>>(s => s.GetJsonWebKeyListAsync())
									.Returns(Task.FromResult(publicEcJsoneWebKeyList));

			// Public Oct Jwks
			var publicOctJwksJson = File.ReadAllText(@"TestData\JwksOctPublic.json")
										.Replace(Environment.NewLine, string.Empty);
			var publicOctJwks = JsonConvert.DeserializeObject<Jwks>(publicOctJwksJson);
			var publicOctJsoneWebKeyList = new List<JsonWebKey>(publicOctJwks.Keys);
			this.publicOctJwksService = new Mock<JwksService>(httpClient, jwkUrl);
			this.publicOctJwksService.Setup<Task<List<JsonWebKey>>>(s => s.GetJsonWebKeyListAsync())
									 .Returns(Task.FromResult(publicOctJsoneWebKeyList));

			// Private RSA Key
			this.privateJsonWebKeyList = new List<JsonWebKey>();
			var privateRsaJson = File.ReadAllText(@"TestData\RsaPrivate.json")
									 .Replace(Environment.NewLine, string.Empty);
			var privateRsaJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateRsaJson);
			this.privateJsonWebKeyList.Add(privateRsaJsonWebKey);

			// Private EC key
			var privateEcJson = File.ReadAllText(@"TestData\EcPrivate.json")
									 .Replace(Environment.NewLine, string.Empty);
			var privateEcJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateEcJson);
			this.privateJsonWebKeyList.Add(privateEcJsonWebKey);

			this.cacheDurationSeconds = 3600;
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetEncryptionKeyAsync_PublicEC_Success()
		{
			// Arrange
			var keyResolver = new KeyResolver(this.cacheDurationSeconds);
			keyResolver.SetJwksService(this.publicEcJwksService.Object);

			// Act
			var jsonWebKey = await keyResolver.GetEncryptionKeyAsync();

			// Assert
			Assert.IsNotNull(jsonWebKey);
			Assert.IsFalse(jsonWebKey.HasPrivateKey);
			Assert.AreEqual("EC", jsonWebKey.Kty);
			Assert.AreEqual(false, jsonWebKey.HasPrivateKey);
			Assert.AreEqual("P-256", jsonWebKey.Crv);
			Assert.AreEqual("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jsonWebKey.X);
			Assert.AreEqual("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jsonWebKey.Y);
			Assert.AreEqual("enc", jsonWebKey.Use);
			Assert.AreEqual("B7B4F5C7-2B46-4F54-A81A-51E8A886B094", jsonWebKey.Kid);
			Assert.AreEqual(256, jsonWebKey.KeySize);
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetEncryptionKeyAsync_PublicRSA_Success()
		{
			// Arrange
			var keyResolver = new KeyResolver(this.cacheDurationSeconds);
			keyResolver.SetJwksService(this.publicRsaJwksService.Object);

			// Act
			var jsonWebKey = await keyResolver.GetEncryptionKeyAsync();

			// Assert
			Assert.IsNotNull(jsonWebKey);
			Assert.IsFalse(jsonWebKey.HasPrivateKey);
			Assert.AreEqual("RSA", jsonWebKey.Kty);
			Assert.AreEqual(false, jsonWebKey.HasPrivateKey);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jsonWebKey.N);
			Assert.AreEqual("AQAB", jsonWebKey.E);
			Assert.AreEqual("RS256", jsonWebKey.Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jsonWebKey.Kid);
			Assert.AreEqual(2048, jsonWebKey.KeySize);
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		[ExpectedExceptionMessage(typeof(EncryptionException), "Unable to retrieve public EC or RSA key from JWK store.")]
		public async Task GetEncryptionKeyAsync_PublicRSA_NoKeysFound_Throws()
		{
			// Arrange
			var keyResolver = new KeyResolver(this.cacheDurationSeconds);
			keyResolver.SetJwksService(this.publicOctJwksService.Object);  // Get Oct key 

			// Act
			await keyResolver.GetEncryptionKeyAsync();

			// Assert
			// EncryptionException: EncryptionException
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetDecryptionKeyAsync_PrivateRSA_Success()
		{
			// Arrange
			var kid = "3072F4C6-193D-481B-BDD2-0F09F5A7DDFB";
			var keyResolver = new KeyResolver(this.cacheDurationSeconds);
			keyResolver.PrivateJsonWebKeyList = this.privateJsonWebKeyList;
			keyResolver.SetJwksService(this.publicEcJwksService.Object);

			// Act
			var jsonWebKey = await keyResolver.GetDecryptionKeyAsync(kid);

			// Assert
			Assert.IsNotNull(jsonWebKey);
			Assert.AreEqual("RSA", jsonWebKey.Kty);
			Assert.AreEqual(true, jsonWebKey.HasPrivateKey);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jsonWebKey.N);
			Assert.AreEqual("AQAB", jsonWebKey.E);
			Assert.AreEqual("RS256", jsonWebKey.Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jsonWebKey.Kid);
			Assert.AreEqual(2048, jsonWebKey.KeySize);
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetEncryptionKeyAsync_PublicRSA_NewJWKSKey_Success()
		{
			// Arrange
			int cacheDurationSeconds = 2;
			var keyResolver = new KeyResolver(cacheDurationSeconds);
			keyResolver.PrivateJsonWebKeyList = this.privateJsonWebKeyList;
			keyResolver.SetJwksService(this.publicEcJwksService.Object);

			// Act
			var jsonWebKey = await keyResolver.GetEncryptionKeyAsync(); // Initial call to JWKS
			Thread.Sleep(2020);
			jsonWebKey = await keyResolver.GetEncryptionKeyAsync();     // Timer expired. Call JWKS
			Thread.Sleep(1000);
			jsonWebKey = await keyResolver.GetEncryptionKeyAsync();     // Timer not expired. Use JWKS cache

			// Assert
			this.publicEcJwksService.Verify(m => m.GetJsonWebKeyListAsync(), Times.Exactly(2));
		}
	}
}

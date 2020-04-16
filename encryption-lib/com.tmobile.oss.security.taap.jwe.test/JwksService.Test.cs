using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Moq.Protected;
using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe.test
{
	[TestClass]
	public class JwksServiceTest
	{
		private string jwkUrl;
		private HttpClient publicRsaHttpClient;
		private HttpClient publicEcHttpClient;


		[TestInitialize]
		public void TestInitialize()
		{
			this.jwkUrl = "https://keyvault-qat.test.px-npe01b.cf.t-mobile.com/jwks/v1/qlab02/chubccpadonotsellsetting";

			// Public RSA Jwks
			var publicRsaJwksJson = File.ReadAllText(@"TestData\JwksRSAPublic.json")
							            .Replace(Environment.NewLine, string.Empty);
			var publicRsaResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
			{
				Content = new StringContent(publicRsaJwksJson, Encoding.UTF8, "application/json")
			};
			var publicRsaKeyHttpMessageHandler = new Mock<HttpMessageHandler>();
			publicRsaKeyHttpMessageHandler.Protected()
								  .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
								  .Returns((HttpRequestMessage request, CancellationToken cancellationToken) => { return Task.FromResult(publicRsaResponse); });
			this.publicRsaHttpClient = new HttpClient(publicRsaKeyHttpMessageHandler.Object, true);

			// Public EC Jwks
			var publicEcJwksJson = File.ReadAllText(@"TestData\JwksECPublic.json")
						   .Replace(Environment.NewLine, string.Empty);
			var publicEcResponse = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
			{
				Content = new StringContent(publicEcJwksJson, Encoding.UTF8, "application/json")
			};
			var mockHttpMessageHandler = new Mock<HttpMessageHandler>();
			mockHttpMessageHandler.Protected()
								  .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
								  .Returns((HttpRequestMessage request, CancellationToken cancellationToken) => { return Task.FromResult(publicEcResponse); });
			this.publicEcHttpClient = new HttpClient(mockHttpMessageHandler.Object, true);
		}

		//[TestMethod]
		//[TestCategory("IntergrationTest")]
		//public async Task GetJsonWebKeyListAsync_PublicRSA_IntergrationSuccess()
		//{
		//	// Arrange
		//	var httpClient = new HttpClient(); // Don't use MOC HttpClient
		//	var jwksService = new JwksService(httpClient, this.jwkUrl);

		//	// Act
		//	var jwksList = await jwksService.GetJsonWebKeyListAsync();

		//	// Assert
		//	Assert.IsNotNull(jwksList);
		//	Assert.IsTrue(jwksList.Count == 1);

		//	Assert.AreEqual("RSA", jwksList[0].Kty);
		//	Assert.AreEqual("chubccpadonotsellsetting", jwksList[0].Kid);
		//	Assert.AreEqual("enc", jwksList[0].Use);
		//	Assert.IsFalse(string.IsNullOrEmpty(jwksList[0].N));  // This will change over time, so just check if exists
		//	Assert.AreEqual("AQAB", jwksList[0].E);
		//	Assert.AreEqual(false, jwksList[0].HasPrivateKey);
		//	Assert.AreEqual(2048, jwksList[0].KeySize);
		//}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetJsonWebKeyListAsync_PublicRSA_Success()
		{
			// Arrange							// Use MOC HttpClient
			var jwksService = new JwksService(this.publicRsaHttpClient, this.jwkUrl);

			// Act
			var jwksList = await jwksService.GetJsonWebKeyListAsync();

			// Assert
			Assert.IsNotNull(jwksList);
			Assert.IsTrue(jwksList.Count == 1);

			Assert.AreEqual("RSA", jwksList[0].Kty);
			Assert.AreEqual(false, jwksList[0].HasPrivateKey);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jwksList[0].N);
			Assert.AreEqual("AQAB", jwksList[0].E);
			Assert.AreEqual("RS256", jwksList[0].Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jwksList[0].Kid);
			Assert.AreEqual(2048, jwksList[0].KeySize);
		}

		[TestMethod]
		[TestCategory("UnitTest")]
		public async Task GetJsonWebKeyListAsync_PublicEC_Success()
		{
			// Arrange							// Use MOC HttpClient
			var jwksService = new JwksService(this.publicEcHttpClient, this.jwkUrl);

			// Act
			var jwksList = await jwksService.GetJsonWebKeyListAsync();

			// Assert
			Assert.IsNotNull(jwksList);
			Assert.IsTrue(jwksList.Count == 1);

			Assert.AreEqual("EC", jwksList[0].Kty);
			Assert.AreEqual(false, jwksList[0].HasPrivateKey);
			Assert.AreEqual("P-256", jwksList[0].Crv);
			Assert.AreEqual("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jwksList[0].X);
			Assert.AreEqual("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jwksList[0].Y);
			Assert.AreEqual("enc", jwksList[0].Use);
			Assert.AreEqual("B7B4F5C7-2B46-4F54-A81A-51E8A886B094", jwksList[0].Kid);
			Assert.AreEqual(256, jwksList[0].KeySize);
		}
	}
}
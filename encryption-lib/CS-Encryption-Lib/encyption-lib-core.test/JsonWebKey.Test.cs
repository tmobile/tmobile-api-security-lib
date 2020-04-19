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
using Newtonsoft.Json;
using System.IO;

namespace com.tmobile.oss.security.taap.jwe.test
{
	[TestClass]
    public class JsonWebKeyTest
    {
		[TestMethod]
		public void Jwks_PublicRSA_FromJsonFile()
		{
			// Arrange
			var jwksJson = File.ReadAllText(@"TestData\JwksRSAPublic.json");

			// Act
			var jwks = JsonConvert.DeserializeObject<Jwks>(jwksJson);
			var jsonWebKey = jwks.Keys[0];

			// Assert
			Assert.AreEqual("RSA", jsonWebKey.Kty);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jsonWebKey.N);
			Assert.AreEqual("RS256", jsonWebKey.Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jsonWebKey.Kid);
		}

		[TestMethod]
		public void JsonWebKey_PrivateRSA_FromJsonFile()
		{
			// Arrange
			var jsonWebKeyJson = File.ReadAllText(@"TestData\RSAPrivate.json");

			// Act
			var jsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(jsonWebKeyJson);

			// Assert
			Assert.AreEqual("RSA", jsonWebKey.Kty);
			Assert.AreEqual("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", jsonWebKey.N);
			Assert.AreEqual("RS256", jsonWebKey.Alg);
			Assert.AreEqual("3072F4C6-193D-481B-BDD2-0F09F5A7DDFB", jsonWebKey.Kid);
			Assert.AreEqual("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q", jsonWebKey.D);
			Assert.AreEqual("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs", jsonWebKey.P);
			Assert.AreEqual("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk", jsonWebKey.Q);
			Assert.AreEqual("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0", jsonWebKey.DP);
			Assert.AreEqual("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk", jsonWebKey.DQ);
			Assert.AreEqual("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU", jsonWebKey.QI);
		}

		[TestMethod]
		public void Jwks_PublicEC_FromJsonFile()
		{
			// Arrange
			var jwksJson = File.ReadAllText(@"TestData\JwksECPublic.json");

			// Act
			var jwks = JsonConvert.DeserializeObject<Jwks>(jwksJson);
			var jsonWebKey = jwks.Keys[0];

			// Assert
			Assert.AreEqual("EC", jsonWebKey.Kty);
			Assert.AreEqual("P-256", jsonWebKey.Crv);
			Assert.AreEqual("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jsonWebKey.X);
			Assert.AreEqual("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jsonWebKey.Y);
			Assert.AreEqual("enc", jsonWebKey.Use);
			Assert.AreEqual("B7B4F5C7-2B46-4F54-A81A-51E8A886B094", jsonWebKey.Kid);
		}

		[TestMethod]
		public void JsonWebKey_PrivateEC_FromJsonFile()
		{
			// Arrange
			var jsonWebKeyJson = File.ReadAllText(@"TestData\ECPrivate.json");
			
			// Act
			var jsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(jsonWebKeyJson);

			// Assert
			Assert.AreEqual("EC", jsonWebKey.Kty);
			Assert.AreEqual("P-256", jsonWebKey.Crv);
			Assert.AreEqual("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", jsonWebKey.X);
			Assert.AreEqual("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", jsonWebKey.Y);
			Assert.AreEqual("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", jsonWebKey.D);
			Assert.AreEqual("enc", jsonWebKey.Use);
			Assert.AreEqual("B7B4F5C7-2B46-4F54-A81A-51E8A886B094", jsonWebKey.Kid);
		}

		[TestMethod]
		public void Jwks_PublicOct_FromJsonFile()
		{
			// Arrange
			var jwksJson = File.ReadAllText(@"TestData\JwksOctPublic.json");

			// Act
			var jwks = JsonConvert.DeserializeObject<Jwks>(jwksJson);
			var jsonWebKey = jwks.Keys[0];

			// Assert
			Assert.AreEqual("OCT", jsonWebKey.Kty);
			Assert.AreEqual("A128KW", jsonWebKey.Alg);
			Assert.AreEqual("GawgguFyGrWKav7AX4VKUg", jsonWebKey.K);
			Assert.AreEqual("40F36B31-44A5-44B4-AC2F-676D5C8CB4C2", jsonWebKey.Kid);
		}

		[TestMethod]
		public void JsonWebKey_PrivateOct_FromJsonFile()
		{
			// Arrange
			var jsonWebKeyJson = File.ReadAllText(@"TestData\OctPrivate.json");

			// Act
			var jsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(jsonWebKeyJson);

			// Assert
			Assert.AreEqual("OCT", jsonWebKey.Kty);
			Assert.AreEqual("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", jsonWebKey.K);
			Assert.AreEqual("40F36B31-44A5-44B4-AC2F-676D5C8CB4C2", jsonWebKey.Kid);
		}
	}
}

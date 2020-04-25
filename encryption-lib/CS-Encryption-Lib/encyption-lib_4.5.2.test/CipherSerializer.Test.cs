//using Microsoft.IdentityModel.Tokens;
//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using System.IO;

//namespace com.tmobile.oss.security.taap.jwe.test
//{
//    [TestClass]
//    public class CipherSerializerTest
//    {
//        private CipherSerializer cipherSerializer;
//        private Jwks expectedJwks;
//        private string expectedJwksJson;

//        [TestInitialize]
//        public void TestInitialize()
//        {
//            this.expectedJwks = new Jwks()
//            {
//                Keys = new JsonWebKey[1]
//                {
//                    new JsonWebKey()
//                    {
//                        Alg = "RS256",
//                        E = "AQAB",
//                        Kid = "3072F4C6-193D-481B-BDD2-0F09F5A7DDFB",
//                        Kty = "RSA",
//                        N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
//                    }
//                }
//            };

//            this.expectedJwksJson = File.ReadAllText(@"TestData\JwksRSAPublic.json");
//        }

//        [TestMethod]
//        public void Deserialize_Success()
//        {
//            // Arrange
//            this.cipherSerializer = new CipherSerializer();

//            // Act
//            var actualJwks = cipherSerializer.Deserialize<Jwks>(this.expectedJwksJson);

//            // Assert
//            Assert.IsNotNull(actualJwks);
//            Assert.IsTrue(actualJwks.Keys.Length == 1);
//            Assert.AreEqual(this.expectedJwks.Keys[0].Alg, actualJwks.Keys[0].Alg);
//            Assert.AreEqual(this.expectedJwks.Keys[0].E, actualJwks.Keys[0].E);
//            Assert.AreEqual(this.expectedJwks.Keys[0].Kid, actualJwks.Keys[0].Kid);
//            Assert.AreEqual(this.expectedJwks.Keys[0].Kty, actualJwks.Keys[0].Kty);
//            Assert.AreEqual(this.expectedJwks.Keys[0].N, actualJwks.Keys[0].N);
//        }

//        [TestMethod]
//        public void Serialize_Success()
//        {
//            // Arrange
//            this.cipherSerializer = new CipherSerializer();

//            // Act
//            var actualJwks = cipherSerializer.Serialize<Jwks>(this.expectedJwks);

//            // Assert
//            Assert.IsFalse(string.IsNullOrEmpty(actualJwks));
//            Assert.IsTrue(actualJwks.Contains("\"Alg\":\"RS256\""));
//            Assert.IsTrue(actualJwks.Contains("\"E\":\"AQAB\""));
//            Assert.IsTrue(actualJwks.Contains("\"Kid\":\"3072F4C6-193D-481B-BDD2-0F09F5A7DDFB\""));
//            Assert.IsTrue(actualJwks.Contains("\"Kty\":\"RSA\""));
//            Assert.IsTrue(actualJwks.Contains("\"N\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""));
//            Assert.IsTrue(actualJwks.Contains("\"HasPrivateKey\":false"));
//            Assert.IsTrue(actualJwks.Contains("\"KeySize\":2048"));
//        }

//        [TestMethod]
//        [ExpectedExceptionMessage(typeof(SerializerException), "Decryption key not found. ID: '11'.")]
//        public void Serialize_Error()
//        {
//            // Arrange
//            this.cipherSerializer = new CipherSerializer();

//            // Act
//            var actualJwks = cipherSerializer.Serialize<Jwks>(new Jwks());

//            // Assert
//        }

//        [TestMethod]
//        [ExpectedExceptionMessage(typeof(SerializerException), "Decryption key not found. ID: '11'.")]
//        public void Deserialize_Error()
//        {
//            // Arrange
//            this.cipherSerializer = new CipherSerializer();

//            // Act
//            var actualJwks = cipherSerializer.Deserialize<Jwks>(null);

//            // Assert
//        }
//    }
//}

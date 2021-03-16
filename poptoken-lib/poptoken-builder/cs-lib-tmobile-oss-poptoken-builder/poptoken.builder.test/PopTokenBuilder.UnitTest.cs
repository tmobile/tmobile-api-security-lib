using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Text;

namespace com.tmobile.oss.security.taap.poptoken.builder.mstest
{
[TestClass]
public class PopTokenBuilderUnitTest
{
string _publicRsaKeyPem;
string _publicRsaKeyXml;

string _privateRsaKeyPem;
string _privateRsaKeyXml;

string audience;
string issuer;

[TestInitialize]
public void TestInitialize()
{
    // 1) Create RSA public/private keys (one time)
    // Download OpenSSL for Windows
    // https://sourceforge.net/projects/gnuwin32/postdownload

    // # Create a 2048 bit Private RSA key in PKCS1 format
    // openssl genrsa -out private-key-pkcs1.pem 2048

    //# Convert the Private RSA key to PKCS8 format. 
    // openssl pkcs8 -topk8 -inform PEM -in private-key-pkcs1.pem -outform PEM -nocrypt -out private-key-pkcs8.pem

    //# Create a Public RSA key in PKCS8 format
    // openssl rsa -in private-key-pkcs8.pem -outform PEM -pubout -out public-key.pem
    //      private-key-pkcs8.pem
    //      public-key.pem

    // Private Key
    var privateKeyPemRsaStringBuilder = new StringBuilder();
    privateKeyPemRsaStringBuilder.AppendLine("-----BEGIN PRIVATE KEY-----");
    privateKeyPemRsaStringBuilder.AppendLine("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfZ1rsV+eOlhU1Yq1LQoxyTwznSEbtUQ+7916ww+xa5lOd3ldSxIJ/f/76oTwSnJtfhFlgxjxKqIRUa8O3NhRVZ5aEvMHpjHMeTNa7ewr7kpqWA5K0dJE8KsCB2Nx0+BGLgCEC3lpF37xZVIkczpzSfnQ4uCyuKPNuP1pZgAE27a5AuJU2pjGS4RXR77AlhHReVI1sT0CMbiTBnD4kJ4G9QfrayqD3FMNMvYOKeBZkLapir+NTblTnAzGyRu69hQLM0Dg9Xx8D28mFYTn8yBENxhZjtqOvxLcmpihp3zYA6fosG3z/gbhZBnTPfy3K1Z6DX/AZs4LgyS0hpoQxZsB3AgMBAAECggEAXOpJBITE08dF+4VWUA0tgp/zfIkT1tcuXbl2d4Dsr5ucV+Q3cGZdTuaUARGky5B/vLCPzKogkMAjynW6cnvSZGnqQdspCPK2U44kiMnTAAtXkmPoysk7sx+UcNuwvXmv+GmqVFq5sgsVZdixx5njrYrKQhmQ6b+zDateBddoXdRH+N9RrU5lwzqhwPnswO79cjPkHd5+3H/2dirNXa5VNK0ykdGd6f0V5aesDcZwl/96VGgOX9T23Ghf4gNt2JoAcp4wKwz2u0AUgM4sJP13FXbfRhB61c9aBjldzoTVpNZofI7xADxjVWl4HRdFB+5e3xGTbDbRU/Vl/4RWpO2c0QKBgQDNswWxPnuWcewQOWvcrmHuciEH4K22WAE/PfDKamInnXMp+OHdOX30v1dI2D+amDFxN0F/MKyMwqvvU471Man+uX3drg/GXBpMHNSEwZsJK6hgLFXMwgDLC4VIMm+e6TkgCFWVZXs2yL7bDPXBN9YEhepa5tmOIrOph/lBbj6WDwKBgQDGYi9HMxCCoYVPSXQ707/2kmMLuqTWuKpJzMKU6hjAbXzc6U5rfGC4fIPDqALX2CCwq3IEoNP6aBjaml2dNtsmTVMgN0JqAPdPeJoGIRp3qbsWz4dF0k72xU7HuvyX2hyCAom48EvsCxxi8giiyYL4ZXmxtTEhfvVvTWY2JgVXGQKBgEbjD+4iA0M4ZUq+Dx7Q9azPpfRqCFNThrJ9rRKEkOjoCL0JKQUs/+wtWG4hH+It2rQSf77OTlh/6fKjEBwNjnDbCbYwev031lQuh0ps0fnaEr955+OVY+KVSMw1nWPdKbORS7UdcNXTXnpsv/BjRpzubXIAJi8mZFXjJxHWZTkfAoGAWB+VUNNmKiEFzsqaT1kolKdCSBuIzbkKK+5BIVU72X7JUHhy1VxSuqDVBzzCxo7DNrdx1ox6nWlQYQrhOsz7XHBM1Kq3Xc9ADJVOFhruXumOqftV47YgTY4oCKEPQ4Un1Li75OMZVqk42tsY6vcIrr6k6EPMp0x2ShLfrH4HMUECgYEAip2YXm8yrDpWOSeL5fnqtA0zFnLc28Bxc47RRcy3jjMPQ9ADfRXfa087Te+WzG0p1wZJWSpTINQjTX+BdUMpmicgU7iX/QDDAVuvKImbb9TBCO0D9OZ+fnogq03MwerZyTuws2pS5BEytgdlcTYG+w+prDZi0ll8U+EQgWeaFUQ=");
    privateKeyPemRsaStringBuilder.AppendLine("-----END PRIVATE KEY-----");
    _privateRsaKeyPem = privateKeyPemRsaStringBuilder.ToString();

    // (Optional) Private Key converted from PEM format to XML format 
    _privateRsaKeyXml = "<RSAKeyValue><Modulus>n2da7FfnjpYVNWKtS0KMck8M50hG7VEPu/desMPsWuZTnd5XUsSCf3/++qE8EpybX4RZYMY8SqiEVGvDtzYUVWeWhLzB6YxzHkzWu3sK+5KalgOStHSRPCrAgdjcdPgRi4AhAt5aRd+8WVSJHM6c0n50OLgsrijzbj9aWYABNu2uQLiVNqYxkuEV0e+wJYR0XlSNbE9AjG4kwZw+JCeBvUH62sqg9xTDTL2DingWZC2qYq/jU25U5wMxskbuvYUCzNA4PV8fA9vJhWE5/MgRDcYWY7ajr8S3JqYoad82AOn6LBt8/4G4WQZ0z38tytWeg1/wGbOC4MktIaaEMWbAdw==</Modulus><Exponent>AQAB</Exponent><P>zbMFsT57lnHsEDlr3K5h7nIhB+CttlgBPz3wympiJ51zKfjh3Tl99L9XSNg/mpgxcTdBfzCsjMKr71OO9TGp/rl93a4PxlwaTBzUhMGbCSuoYCxVzMIAywuFSDJvnuk5IAhVlWV7Nsi+2wz1wTfWBIXqWubZjiKzqYf5QW4+lg8=</P><Q>xmIvRzMQgqGFT0l0O9O/9pJjC7qk1riqSczClOoYwG183OlOa3xguHyDw6gC19ggsKtyBKDT+mgY2ppdnTbbJk1TIDdCagD3T3iaBiEad6m7Fs+HRdJO9sVOx7r8l9ocggKJuPBL7AscYvIIosmC+GV5sbUxIX71b01mNiYFVxk=</Q><DP>RuMP7iIDQzhlSr4PHtD1rM+l9GoIU1OGsn2tEoSQ6OgIvQkpBSz/7C1YbiEf4i3atBJ/vs5OWH/p8qMQHA2OcNsJtjB6/TfWVC6HSmzR+doSv3nn45Vj4pVIzDWdY90ps5FLtR1w1dNeemy/8GNGnO5tcgAmLyZkVeMnEdZlOR8=</DP><DQ>WB+VUNNmKiEFzsqaT1kolKdCSBuIzbkKK+5BIVU72X7JUHhy1VxSuqDVBzzCxo7DNrdx1ox6nWlQYQrhOsz7XHBM1Kq3Xc9ADJVOFhruXumOqftV47YgTY4oCKEPQ4Un1Li75OMZVqk42tsY6vcIrr6k6EPMp0x2ShLfrH4HMUE=</DQ><InverseQ>ip2YXm8yrDpWOSeL5fnqtA0zFnLc28Bxc47RRcy3jjMPQ9ADfRXfa087Te+WzG0p1wZJWSpTINQjTX+BdUMpmicgU7iX/QDDAVuvKImbb9TBCO0D9OZ+fnogq03MwerZyTuws2pS5BEytgdlcTYG+w+prDZi0ll8U+EQgWeaFUQ=</InverseQ><D>XOpJBITE08dF+4VWUA0tgp/zfIkT1tcuXbl2d4Dsr5ucV+Q3cGZdTuaUARGky5B/vLCPzKogkMAjynW6cnvSZGnqQdspCPK2U44kiMnTAAtXkmPoysk7sx+UcNuwvXmv+GmqVFq5sgsVZdixx5njrYrKQhmQ6b+zDateBddoXdRH+N9RrU5lwzqhwPnswO79cjPkHd5+3H/2dirNXa5VNK0ykdGd6f0V5aesDcZwl/96VGgOX9T23Ghf4gNt2JoAcp4wKwz2u0AUgM4sJP13FXbfRhB61c9aBjldzoTVpNZofI7xADxjVWl4HRdFB+5e3xGTbDbRU/Vl/4RWpO2c0Q==</D></RSAKeyValue>";

    // Public Key
    var publicKeyPemRsaStringBuilder = new StringBuilder();
    publicKeyPemRsaStringBuilder.AppendLine("-----BEGIN PUBLIC KEY-----");
    publicKeyPemRsaStringBuilder.AppendLine("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn2da7FfnjpYVNWKtS0KMck8M50hG7VEPu/desMPsWuZTnd5XUsSCf3/++qE8EpybX4RZYMY8SqiEVGvDtzYUVWeWhLzB6YxzHkzWu3sK+5KalgOStHSRPCrAgdjcdPgRi4AhAt5aRd+8WVSJHM6c0n50OLgsrijzbj9aWYABNu2uQLiVNqYxkuEV0e+wJYR0XlSNbE9AjG4kwZw+JCeBvUH62sqg9xTDTL2DingWZC2qYq/jU25U5wMxskbuvYUCzNA4PV8fA9vJhWE5/MgRDcYWY7ajr8S3JqYoad82AOn6LBt8/4G4WQZ0z38tytWeg1/wGbOC4MktIaaEMWbAdwIDAQAB");
    publicKeyPemRsaStringBuilder.AppendLine("-----END PUBLIC KEY-----");
    _publicRsaKeyPem = publicKeyPemRsaStringBuilder.ToString();

    // (Optional) Public Key converted from PEM format to XML format
    _publicRsaKeyXml = "<RSAKeyValue><Modulus>n2da7FfnjpYVNWKtS0KMck8M50hG7VEPu/desMPsWuZTnd5XUsSCf3/++qE8EpybX4RZYMY8SqiEVGvDtzYUVWeWhLzB6YxzHkzWu3sK+5KalgOStHSRPCrAgdjcdPgRi4AhAt5aRd+8WVSJHM6c0n50OLgsrijzbj9aWYABNu2uQLiVNqYxkuEV0e+wJYR0XlSNbE9AjG4kwZw+JCeBvUH62sqg9xTDTL2DingWZC2qYq/jU25U5wMxskbuvYUCzNA4PV8fA9vJhWE5/MgRDcYWY7ajr8S3JqYoad82AOn6LBt8/4G4WQZ0z38tytWeg1/wGbOC4MktIaaEMWbAdw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    // 3) Setup Audience/Issuer
    audience = "123";
    issuer = "abc"; 
}

/// <summary>
/// Example 1a: Calling oAuth2 server to get bearer token with poptoken (Pem Format)
/// </summary>
[TestMethod]
public void PopTokenBuilder_Build_ValidateToken_OAuth2Example_PEMFormat_Success_Test()
{
    // Arrange
    var keyValuePairDictionary = new Dictionary<string, string>
    {
        { PopEhtsKeyEnum.Authorization.GetDescription(), "Basic UtKV75JJbVAewOrkHMXhLbiQ11SS" },
        { PopEhtsKeyEnum.Uri.GetDescription(), "/oauth2/v6/tokens" },
        { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
    };

    var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
    var popTokenBuilder = new PopTokenBuilder(audience, issuer);

    // Act         
    var popToken = popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                    .SignWith(_privateRsaKeyPem)    // PEM format
                                    .Build();

    var publicRsaSecurityKey = PopTokenBuilderUtils.CreateRsaSecurityKey(_publicRsaKeyPem); // PEM format
    var tokenValidationResult = PopTokenBuilderUtils.ValidateToken(popToken, issuer, audience, publicRsaSecurityKey);

    // Assert
    Assert.IsNotNull(popToken);
    Assert.IsNotNull(tokenValidationResult);
    Assert.IsTrue(tokenValidationResult.IsValid);
    Assert.IsTrue(tokenValidationResult.Claims.Count == 9);
}

/// <summary>
/// Example 1a: Calling oAuth2 server to get bearer token with poptoken (Xml Format - Optional)
/// </summary>
[TestMethod]
public void PopTokenBuilder_Build_ValidateToken_OAuth2Example_XMLFormat_Success_Test()
{
    // Arrange
    var keyValuePairDictionary = new Dictionary<string, string>
    {
        { PopEhtsKeyEnum.Authorization.GetDescription(), "Basic UtKV75JJbVAewOrkHMXhLbiQ11SS" },
        { PopEhtsKeyEnum.Uri.GetDescription(), "/oauth2/v6/tokens" },
        { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
    };

    var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
    var popTokenBuilder = new PopTokenBuilder(audience, issuer);

    // Act         
    var popToken = popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                    .SignWith(_privateRsaKeyXml)  // XML format
                                    .Build();

    var publicRsaSecurityKey = PopTokenBuilderUtils.CreateRsaSecurityKey(_publicRsaKeyXml); // XML format
    var tokenValidationResult = PopTokenBuilderUtils.ValidateToken(popToken, issuer, audience, publicRsaSecurityKey);

    // Assert
    Assert.IsNotNull(popToken);
    Assert.IsNotNull(tokenValidationResult);
    Assert.IsTrue(tokenValidationResult.IsValid);
    Assert.IsTrue(tokenValidationResult.Claims.Count == 9);
}

/// <summary>
/// Example 2a: Using bearer token to call WebApi endpoint with poptoken (Pem Format)
/// </summary>
[TestMethod]
public void PopTokenBuilder_Build_ValidateToken_ApiExample_PEMFormat_Success_Test()
{
    // Arrange
    var keyValuePairDictionary = new Dictionary<string, string>
    {
        { PopEhtsKeyEnum.ContentType.GetDescription(), PopEhtsKeyEnum.ApplicationJson.GetDescription() },
        { PopEhtsKeyEnum.CacheControl.GetDescription(), PopEhtsKeyEnum.NoCache.GetDescription() },
        { PopEhtsKeyEnum.Authorization.GetDescription(), "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS" },
        { PopEhtsKeyEnum.Uri.GetDescription(), "/commerce/v1/orders" },
        { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
        { PopEhtsKeyEnum.Body.GetDescription(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}" }
    };

    var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
    var popTokenBuilder = new PopTokenBuilder(audience, issuer);

    // Act         
    var popToken = popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                    .SignWith(_privateRsaKeyPem)   // Pem format
                                    .Build();

    var publicRsaSecurityKey = PopTokenBuilderUtils.CreateRsaSecurityKey(_publicRsaKeyPem); // Pem format
    var tokenValidationResult = PopTokenBuilderUtils.ValidateToken(popToken, issuer, audience, publicRsaSecurityKey);

    // Assert
    Assert.IsNotNull(popToken);
    Assert.IsNotNull(tokenValidationResult);
    Assert.IsTrue(tokenValidationResult.IsValid);
    Assert.IsTrue(tokenValidationResult.Claims.Count == 9);
}

/// <summary>
/// Example 2b: Using bearer token to call WebApi endpoint with poptoken (Xml Format - Optional)
/// </summary>
[TestMethod]
public void PopTokenBuilder_Build_ValidateToken_ApiExample_XmlFormat_Success_Test()
{
    // Arrange
    var keyValuePairDictionary = new Dictionary<string, string>
    {
        { PopEhtsKeyEnum.ContentType.GetDescription(), PopEhtsKeyEnum.ApplicationJson.GetDescription() },
        { PopEhtsKeyEnum.CacheControl.GetDescription(), PopEhtsKeyEnum.NoCache.GetDescription() },
        { PopEhtsKeyEnum.Authorization.GetDescription(), "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS" },
        { PopEhtsKeyEnum.Uri.GetDescription(), "/commerce/v1/orders" },
        { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
        { PopEhtsKeyEnum.Body.GetDescription(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}" }
    };

    var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
    var popTokenBuilder = new PopTokenBuilder(audience, issuer);

    // Act         
    var popToken = popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                    .SignWith(_privateRsaKeyXml)   // XML format
                                    .Build();

    var publicRsaSecurityKey = PopTokenBuilderUtils.CreateRsaSecurityKey(_publicRsaKeyXml); // XML format
    var tokenValidationResult = PopTokenBuilderUtils.ValidateToken(popToken, issuer, audience, publicRsaSecurityKey);

    //Assert
    Assert.IsNotNull(popToken);
    Assert.IsNotNull(tokenValidationResult);
    Assert.IsTrue(tokenValidationResult.IsValid);
    Assert.IsTrue(tokenValidationResult.Claims.Count == 9);
}

        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values")]
        public void PopTokenBuilder_Build_EhtsKeyValueMap_Null_Test()
        {
            // Arrange
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);

            HashSet<KeyValuePair<string, string>> ehtsKeyValueMap = null;   // ehtsKeyValueMap is null

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(ehtsKeyValueMap)
                                          .SignWith(_privateRsaKeyPem)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }

        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "The ehtsKeyValueMap should not contain more than 100 entries")]
        public void PopTokenBuilder_Build_EhtsKeyValueMap_GreaterThan100_Test()
        {
            // Arrange
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);
            var keyValuePairDictionary = new Dictionary<string, string>();
            for(var i = 0; i<101; i++)                                      // Create 101 key value pairs
            {
                keyValuePairDictionary.Add(popTokenBuilder.GetUniqueIdentifier(), popTokenBuilder.GetUniqueIdentifier());
            }

            var ehtsKeyValueMap = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(ehtsKeyValueMap)
                                          .SignWith(_privateRsaKeyPem)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }

        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "A privateKeyXmlOrPemRsa shall be provided to sign the PoP token")]
        public void PopTokenBuilder_Build_Both_RsaSecurityKey_privateKeyXmlRsa_Null_Test()
        {
            // Arrange
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);
            var keyValuePairDictionary = new Dictionary<string, string>();
            for (var i = 0; i < 100; i++)
            {
                keyValuePairDictionary.Add(popTokenBuilder.GetUniqueIdentifier(), popTokenBuilder.GetUniqueIdentifier());
            }
            var ehtsKeyValueMap = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
            _privateRsaKeyPem = null;                                            // privateKeyXmlRsa is null

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(ehtsKeyValueMap)
                                          .SignWith(_privateRsaKeyPem)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }

        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values")]
        public void PopTokenBuilder_DoesContainAnyEmptyKeysOrValues_ValueIsNull_Test()
        {
            // Arrange
            var keyValuePairDictionary = new Dictionary<string, string>
            {
                { PopEhtsKeyEnum.ContentType.GetDescription(), null },    // Value is null
                { PopEhtsKeyEnum.Authorization.GetDescription(), "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS" },
                { PopEhtsKeyEnum.Uri.GetDescription(), "/commerce/v1/orders" },
                { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
                { PopEhtsKeyEnum.Body.GetDescription(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}" }
            };
            var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                          .SignWith(_privateRsaKeyPem)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }

        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values")]
        public void PopTokenBuilder_DoesContainAnyEmptyKeysOrValues_KeyIsEmpty_Test()
        {
            // Arrange
            var keyValuePairDictionary = new Dictionary<string, string>
            {
                { string.Empty, PopEhtsKeyEnum.ApplicationJson.GetDescription() },   // Key is empty
                { PopEhtsKeyEnum.Authorization.GetDescription(), "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS" },
                { PopEhtsKeyEnum.Uri.GetDescription(), "/commerce/v1/orders" },
                { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
                { PopEhtsKeyEnum.Body.GetDescription(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}" }
            };
            var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                          .SignWith(_privateRsaKeyPem)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }
    }
}

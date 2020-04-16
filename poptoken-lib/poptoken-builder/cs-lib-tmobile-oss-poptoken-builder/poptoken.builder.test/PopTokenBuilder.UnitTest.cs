using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace com.tmobile.oss.security.taap.poptoken.builder.test
{
    [TestClass]
    public class PopTokenBuilderUnitTest
    {
        string privateKeyPemRsa;
        string privateKeyXmlRsa;

        string audience;
        string issuer;

        [TestInitialize]
        public void TestInitialize()
        {
            // Private Key
            var privateKeyPemRsaStringBuilder = new StringBuilder();
            privateKeyPemRsaStringBuilder.AppendLine("-----BEGIN PRIVATE KEY-----");
            privateKeyPemRsaStringBuilder.AppendLine("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDZPQF1bZdaY80nB/xK+8KdApRhv/nlaIuHR6jaoEih0YAz5N3cd++zH5BY+HX9Muc8pAbmtypMs5o2HIcS12Qm+H998eXWcL8rVUJURLqZpObWY0egPomOqowwZGHFhbTG02bRZWjANIFTQj2BukOi/6m9o4GvlhGrGSdjXhskrFmWPTO/gT6Dv3SJ8eLdKeQU1AV17JB4vreJgWs1ZRPtdwPNc+ef3UzS8w710ykjSGSxDWF7SaUqn8KUAL1DMmBgD1bectIYsT2646KkABSayYGAe+6UjdYAN2OLYvEbScGdDDtZgQxIu1GDASoFn1xh5iJ5o7sq51zQM/dBhLWbAgMBAAECggEATOwDJjeGDmWkcRusxEhdYwdUz0ARFqBsN5yyN6fl0BbE1JtHzBdT8xNMI5TnAp8RrjFOmEdnXP2Dr4Fuesd2GS6IxmnvPn1x08A+2mPzxw/TBTrmU+GRB8lwFnqU/EIZ/wVANQk5jEWLPZYI/XSdGox46EOLWkdDPliLz+20oskVdMF0JwC0/pwFuleUUv5ryPZ40c4OP/VfXDcjYY66GWHKgWUVmp9CxMqWwfFbwKqjZh+s3vMEqGjwwZ7PNRylFTkyeaIu9KcMaoQy5VZodyzaf3cVofkW9Ue2Ty6Rrn+37W+3ZUYmFRLLAatoDm4K4m2zbS8T4zWJwB3Qpma3kQKBgQDtW5G+xVIwv7cMXPkXpkmM9VYDb72XlwxbiPS20oywh7e8rWM3ikC+I0tnJKmd/Ek7iacNvVsdoBm0rEE/KwCUCiBklAFIT5EMuzBdshX8hgusvdBHxaGFrMFyXMFWvof/dAolHRtZxfeOrRLlq1Q8QjEhu2TtDHIHkO31MF/61QKBgQDqTOfxwxUV2TPNOKxLCuViXCnRIQC0dpsXFMELCvz5EspgfCPC86WLOL2zoxfJN0wSkyUTONjvEXeLv3cdrc6fJs2cuGZHiuKfhLwlLdLoYoWju3uE/ucYuPdkTGKJYkeAT4jXDtHQezWbSw9daxrFN9DThpiiinbd6SpVEQpGrwKBgEajacyMjNlVNPTI9pjDNEBvAxoitxnWKidTqwB9yMEAov3T3CM7UelEN7yKfLA31NOTM9Qy9lrquru6R/C0q4djPCCyq28JvvE7BDneNgzhF7hhBQtXFariru+KCz/1lCPCNQK2lt0wvWwItgcD5h3I1TZkvrSNb6Iwz6CYtPfBAoGAaKDjSxEEz3bpLRHLzs8U1DG38s28FNqKM2pvMlE72rZLbX7CMYLAQEWcYSXJr29kJz9SZR0Tst6n9d4QgU5mYKfhVcT616Prw7RwmGG4N1IXv6Avbpqt9FpVD5MUxaj/qQrbXr4db+41aB3CxMLZd4yPUoZejucqYbqHzukHH70CgYA/9osJo6W+MRTYWkDonnj37HivtmbHxNukxU9UmlNuxXJDn8D9w/M5b4PTi0isg/jZ9oJ/gqnJwDuXmIHebk2Qi0EHXPaRZE0ECATwWHt1MzqPHGifU3OZ1S5XVtEjXghFTa9A1T+JObhayAdNYCbPxw3OGu4FvOR3eWFQNkfA4g==");
            privateKeyPemRsaStringBuilder.AppendLine("-----END PRIVATE KEY-----");
            privateKeyPemRsa = privateKeyPemRsaStringBuilder.ToString();
            // Converted key from PEM format to XML format
            privateKeyXmlRsa = "<RSAKeyValue><Modulus>2T0BdW2XWmPNJwf8SvvCnQKUYb/55WiLh0eo2qBIodGAM+Td3Hfvsx+QWPh1/TLnPKQG5rcqTLOaNhyHEtdkJvh/ffHl1nC/K1VCVES6maTm1mNHoD6JjqqMMGRhxYW0xtNm0WVowDSBU0I9gbpDov+pvaOBr5YRqxknY14bJKxZlj0zv4E+g790ifHi3SnkFNQFdeyQeL63iYFrNWUT7XcDzXPnn91M0vMO9dMpI0hksQ1he0mlKp/ClAC9QzJgYA9W3nLSGLE9uuOipAAUmsmBgHvulI3WADdji2LxG0nBnQw7WYEMSLtRgwEqBZ9cYeYieaO7Kudc0DP3QYS1mw==</Modulus><Exponent>AQAB</Exponent><P>7VuRvsVSML+3DFz5F6ZJjPVWA2+9l5cMW4j0ttKMsIe3vK1jN4pAviNLZySpnfxJO4mnDb1bHaAZtKxBPysAlAogZJQBSE+RDLswXbIV/IYLrL3QR8WhhazBclzBVr6H/3QKJR0bWcX3jq0S5atUPEIxIbtk7QxyB5Dt9TBf+tU=</P><Q>6kzn8cMVFdkzzTisSwrlYlwp0SEAtHabFxTBCwr8+RLKYHwjwvOlizi9s6MXyTdMEpMlEzjY7xF3i793Ha3OnybNnLhmR4rin4S8JS3S6GKFo7t7hP7nGLj3ZExiiWJHgE+I1w7R0Hs1m0sPXWsaxTfQ04aYoop23ekqVREKRq8=</Q><DP>RqNpzIyM2VU09Mj2mMM0QG8DGiK3GdYqJ1OrAH3IwQCi/dPcIztR6UQ3vIp8sDfU05Mz1DL2Wuq6u7pH8LSrh2M8ILKrbwm+8TsEOd42DOEXuGEFC1cVquKu74oLP/WUI8I1AraW3TC9bAi2BwPmHcjVNmS+tI1vojDPoJi098E=</DP><DQ>aKDjSxEEz3bpLRHLzs8U1DG38s28FNqKM2pvMlE72rZLbX7CMYLAQEWcYSXJr29kJz9SZR0Tst6n9d4QgU5mYKfhVcT616Prw7RwmGG4N1IXv6Avbpqt9FpVD5MUxaj/qQrbXr4db+41aB3CxMLZd4yPUoZejucqYbqHzukHH70=</DQ><InverseQ>P/aLCaOlvjEU2FpA6J549+x4r7Zmx8TbpMVPVJpTbsVyQ5/A/cPzOW+D04tIrIP42faCf4KpycA7l5iB3m5NkItBB1z2kWRNBAgE8Fh7dTM6jxxon1NzmdUuV1bRI14IRU2vQNU/iTm4WsgHTWAmz8cNzhruBbzkd3lhUDZHwOI=</InverseQ><D>TOwDJjeGDmWkcRusxEhdYwdUz0ARFqBsN5yyN6fl0BbE1JtHzBdT8xNMI5TnAp8RrjFOmEdnXP2Dr4Fuesd2GS6IxmnvPn1x08A+2mPzxw/TBTrmU+GRB8lwFnqU/EIZ/wVANQk5jEWLPZYI/XSdGox46EOLWkdDPliLz+20oskVdMF0JwC0/pwFuleUUv5ryPZ40c4OP/VfXDcjYY66GWHKgWUVmp9CxMqWwfFbwKqjZh+s3vMEqGjwwZ7PNRylFTkyeaIu9KcMaoQy5VZodyzaf3cVofkW9Ue2Ty6Rrn+37W+3ZUYmFRLLAatoDm4K4m2zbS8T4zWJwB3Qpma3kQ==</D></RSAKeyValue>";

            // ClientId
            audience = "JYM89zuJAf3D1N0omc0VzaoehUW5Inn2";
            issuer = "JYM89zuJAf3D1N0omc0VzaoehUW5Inn2";
        }

        [TestMethod]
        public void PopTokenBuilder_Build_ValidPopToken_Success_Test()
        {
            // Arrange
            var keyValuePairDictionary = new Dictionary<string, string>
            {
                { PopEhtsKeyEnum.ContentType.GetDescription(), PopEhtsKeyEnum.ApplicationJson.GetDescription() },
                { PopEhtsKeyEnum.Authorization.GetDescription(), "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS" },
                { PopEhtsKeyEnum.Uri.GetDescription(), "/commerce/v1/orders" },
                { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
                { PopEhtsKeyEnum.Body.GetDescription(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}" }
            };
            var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);

            // Act
            var popToken = popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                          .SignWith(privateKeyXmlRsa)
                                          .Build();
            // Assert
            Assert.IsTrue(!string.IsNullOrEmpty(popToken));
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
                                          .SignWith(privateKeyXmlRsa)
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
                                          .SignWith(privateKeyXmlRsa)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }

        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "Either rsaSecurityKey or privateKeyXmlRsa should be provided to sign the PoP token")]
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
            popTokenBuilder.rsaSecurityKey = null;                              // rsaSecurityKey is null
            privateKeyXmlRsa = null;                                            // privateKeyXmlRsa is null

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(ehtsKeyValueMap)
                                          .SignWith(privateKeyXmlRsa)
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
                                          .SignWith(privateKeyXmlRsa)
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
                                          .SignWith(privateKeyXmlRsa)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }


        [TestMethod]
        [ExpectedException(typeof(PopTokenBuilderException), "Error occurred while building the PoP token builder, error: Data at the root level is invalid. Line 1, position 1.")]
        public void PopTokenBuilder_Build_ValidPopToken_GeneralException_Test()
        {
            // Arrange
            var keyValuePairDictionary = new Dictionary<string, string>
            {
                { PopEhtsKeyEnum.ContentType.GetDescription(), PopEhtsKeyEnum.ApplicationJson.GetDescription() },
                { PopEhtsKeyEnum.Authorization.GetDescription(), "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS" },
                { PopEhtsKeyEnum.Uri.GetDescription(), "/commerce/v1/orders" },
                { PopEhtsKeyEnum.HttpMethod.GetDescription(), PopEhtsKeyEnum.Post.GetDescription() },
                { PopEhtsKeyEnum.Body.GetDescription(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}" }
            };
            var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(keyValuePairDictionary);
            var popTokenBuilder = new PopTokenBuilder(audience, issuer);

            privateKeyXmlRsa = privateKeyPemRsa;                            // Use Pem format rather then XML format

            // Act
            popTokenBuilder.SetEhtsKeyValueMap(hashMapKeyValuePair)
                                          .SignWith(privateKeyXmlRsa)
                                          .Build();
            // Assert
            // Expected: PopTokenBuilderException
        }
    }
}

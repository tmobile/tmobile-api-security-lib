using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;

namespace com.tmobile.oss.security.taap.poptoken.builder.mstest
{
    [TestClass]
    public class ExtensionsTest
    {
        enum NoDescriptionsEnum { FooBar };

        [TestMethod]
        public void Extensions_GetDescription_Found_Test()
        {
            // Arrange
            var body = PopEhtsKeyEnum.Body;
            var httpMethod = PopEhtsKeyEnum.HttpMethod;
            var uri = PopEhtsKeyEnum.Uri;

            // Act
            var bodyDescription = body.GetDescription();
            var httpMethodDescription = httpMethod.GetDescription();
            var uriDescription = uri.GetDescription();

            // Assert
            Assert.AreEqual("body", bodyDescription);
            Assert.AreEqual("http-method", httpMethodDescription);
            Assert.AreEqual("uri", uriDescription);
        }

        [TestMethod]
        public void Extensions_GetDescription_NotFound_Test()
        {
            // Arrange
            var fooBar = NoDescriptionsEnum.FooBar;

            // Act
            var fooBarDescription = fooBar.GetDescription();

            // Assert
            Assert.AreEqual("FooBar", fooBarDescription);
        }

        [TestMethod]
        public void Extensions_FromXmlRsaPemKey_ValidXmlRsaPrivateKey_Test()
        {
            // Arrange
            var rsa = RSA.Create();
            rsa.KeySize = 2048;
            var expectedPrivateKeyXmlRsa = "<RSAKeyValue><Modulus>2T0BdW2XWmPNJwf8SvvCnQKUYb/55WiLh0eo2qBIodGAM+Td3Hfvsx+QWPh1/TLnPKQG5rcqTLOaNhyHEtdkJvh/ffHl1nC/K1VCVES6maTm1mNHoD6JjqqMMGRhxYW0xtNm0WVowDSBU0I9gbpDov+pvaOBr5YRqxknY14bJKxZlj0zv4E+g790ifHi3SnkFNQFdeyQeL63iYFrNWUT7XcDzXPnn91M0vMO9dMpI0hksQ1he0mlKp/ClAC9QzJgYA9W3nLSGLE9uuOipAAUmsmBgHvulI3WADdji2LxG0nBnQw7WYEMSLtRgwEqBZ9cYeYieaO7Kudc0DP3QYS1mw==</Modulus><Exponent>AQAB</Exponent><P>7VuRvsVSML+3DFz5F6ZJjPVWA2+9l5cMW4j0ttKMsIe3vK1jN4pAviNLZySpnfxJO4mnDb1bHaAZtKxBPysAlAogZJQBSE+RDLswXbIV/IYLrL3QR8WhhazBclzBVr6H/3QKJR0bWcX3jq0S5atUPEIxIbtk7QxyB5Dt9TBf+tU=</P><Q>6kzn8cMVFdkzzTisSwrlYlwp0SEAtHabFxTBCwr8+RLKYHwjwvOlizi9s6MXyTdMEpMlEzjY7xF3i793Ha3OnybNnLhmR4rin4S8JS3S6GKFo7t7hP7nGLj3ZExiiWJHgE+I1w7R0Hs1m0sPXWsaxTfQ04aYoop23ekqVREKRq8=</Q><DP>RqNpzIyM2VU09Mj2mMM0QG8DGiK3GdYqJ1OrAH3IwQCi/dPcIztR6UQ3vIp8sDfU05Mz1DL2Wuq6u7pH8LSrh2M8ILKrbwm+8TsEOd42DOEXuGEFC1cVquKu74oLP/WUI8I1AraW3TC9bAi2BwPmHcjVNmS+tI1vojDPoJi098E=</DP><DQ>aKDjSxEEz3bpLRHLzs8U1DG38s28FNqKM2pvMlE72rZLbX7CMYLAQEWcYSXJr29kJz9SZR0Tst6n9d4QgU5mYKfhVcT616Prw7RwmGG4N1IXv6Avbpqt9FpVD5MUxaj/qQrbXr4db+41aB3CxMLZd4yPUoZejucqYbqHzukHH70=</DQ><InverseQ>P/aLCaOlvjEU2FpA6J549+x4r7Zmx8TbpMVPVJpTbsVyQ5/A/cPzOW+D04tIrIP42faCf4KpycA7l5iB3m5NkItBB1z2kWRNBAgE8Fh7dTM6jxxon1NzmdUuV1bRI14IRU2vQNU/iTm4WsgHTWAmz8cNzhruBbzkd3lhUDZHwOI=</InverseQ><D>TOwDJjeGDmWkcRusxEhdYwdUz0ARFqBsN5yyN6fl0BbE1JtHzBdT8xNMI5TnAp8RrjFOmEdnXP2Dr4Fuesd2GS6IxmnvPn1x08A+2mPzxw/TBTrmU+GRB8lwFnqU/EIZ/wVANQk5jEWLPZYI/XSdGox46EOLWkdDPliLz+20oskVdMF0JwC0/pwFuleUUv5ryPZ40c4OP/VfXDcjYY66GWHKgWUVmp9CxMqWwfFbwKqjZh+s3vMEqGjwwZ7PNRylFTkyeaIu9KcMaoQy5VZodyzaf3cVofkW9Ue2Ty6Rrn+37W+3ZUYmFRLLAatoDm4K4m2zbS8T4zWJwB3Qpma3kQ==</D></RSAKeyValue>";

            // Act
            rsa.FromXmlRsaPemKey(expectedPrivateKeyXmlRsa);
            var actualPrivateKeyXmlRsa =  rsa.ToXmlString(true);

            // Assert
            Assert.AreEqual(expectedPrivateKeyXmlRsa, actualPrivateKeyXmlRsa);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException), "Invalid RSA key string. Must use XML format with <RSAKeyValue> as root.")]
        public void Extensions_FromXmlRsaPemKey_InvalidFormat_Test()
        {
            // Arrange                     
            var rsa = RSA.Create();
            rsa.KeySize = 2048;            // Use wrong format (PEM)
            var expectedPrivateKeyXmlRsa = "-----BEGIN PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDZPQF1bZdaY80nB/xK+8KdApRhv/nlaIuHR6jaoEih0YAz5N3cd++zH5BY+HX9Muc8pAbmtypMs5o2HIcS12Qm+H998eXWcL8rVUJURLqZpObWY0egPomOqowwZGHFhbTG02bRZWjANIFTQj2BukOi/6m9o4GvlhGrGSdjXhskrFmWPTO/gT6Dv3SJ8eLdKeQU1AV17JB4vreJgWs1ZRPtdwPNc+ef3UzS8w710ykjSGSxDWF7SaUqn8KUAL1DMmBgD1bectIYsT2646KkABSayYGAe+6UjdYAN2OLYvEbScGdDDtZgQxIu1GDASoFn1xh5iJ5o7sq51zQM/dBhLWbAgMBAAECggEATOwDJjeGDmWkcRusxEhdYwdUz0ARFqBsN5yyN6fl0BbE1JtHzBdT8xNMI5TnAp8RrjFOmEdnXP2Dr4Fuesd2GS6IxmnvPn1x08A+2mPzxw/TBTrmU+GRB8lwFnqU/EIZ/wVANQk5jEWLPZYI/XSdGox46EOLWkdDPliLz+20oskVdMF0JwC0/pwFuleUUv5ryPZ40c4OP/VfXDcjYY66GWHKgWUVmp9CxMqWwfFbwKqjZh+s3vMEqGjwwZ7PNRylFTkyeaIu9KcMaoQy5VZodyzaf3cVofkW9Ue2Ty6Rrn+37W+3ZUYmFRLLAatoDm4K4m2zbS8T4zWJwB3Qpma3kQKBgQDtW5G+xVIwv7cMXPkXpkmM9VYDb72XlwxbiPS20oywh7e8rWM3ikC+I0tnJKmd/Ek7iacNvVsdoBm0rEE/KwCUCiBklAFIT5EMuzBdshX8hgusvdBHxaGFrMFyXMFWvof/dAolHRtZxfeOrRLlq1Q8QjEhu2TtDHIHkO31MF/61QKBgQDqTOfxwxUV2TPNOKxLCuViXCnRIQC0dpsXFMELCvz5EspgfCPC86WLOL2zoxfJN0wSkyUTONjvEXeLv3cdrc6fJs2cuGZHiuKfhLwlLdLoYoWju3uE/ucYuPdkTGKJYkeAT4jXDtHQezWbSw9daxrFN9DThpiiinbd6SpVEQpGrwKBgEajacyMjNlVNPTI9pjDNEBvAxoitxnWKidTqwB9yMEAov3T3CM7UelEN7yKfLA31NOTM9Qy9lrquru6R/C0q4djPCCyq28JvvE7BDneNgzhF7hhBQtXFariru+KCz/1lCPCNQK2lt0wvWwItgcD5h3I1TZkvrSNb6Iwz6CYtPfBAoGAaKDjSxEEz3bpLRHLzs8U1DG38s28FNqKM2pvMlE72rZLbX7CMYLAQEWcYSXJr29kJz9SZR0Tst6n9d4QgU5mYKfhVcT616Prw7RwmGG4N1IXv6Avbpqt9FpVD5MUxaj/qQrbXr4db+41aB3CxMLZd4yPUoZejucqYbqHzukHH70CgYA/9osJo6W+MRTYWkDonnj37HivtmbHxNukxU9UmlNuxXJDn8D9w/M5b4PTi0isg/jZ9oJ/gqnJwDuXmIHebk2Qi0EHXPaRZE0ECATwWHt1MzqPHGifU3OZ1S5XVtEjXghFTa9A1T+JObhayAdNYCbPxw3OGu4FvOR3eWFQNkfA4g==-----END PRIVATE KEY-----";

            // Act
            rsa.FromXmlRsaPemKey(expectedPrivateKeyXmlRsa);

            // Assert
            // Expected ArgumentException
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException), "Invalid RSA key string. Must use XML format with <RSAKeyValue> as root.")]
        public void Extensions_FromXmlRsaPemKey_EmptyXmlRsaPrivateKey_Test()
        {
            // Arrange                     
            var rsa = RSA.Create();
            rsa.KeySize = 2048;            // Use empty string
            var expectedPrivateKeyXmlRsa = string.Empty;

            // Act
            rsa.FromXmlRsaPemKey(expectedPrivateKeyXmlRsa);

            // Assert
            // Expected ArgumentException
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException), "The specified RSA parameters are not valid; both Exponent and Modulus are required fields.")]
        public void Extensions_FromXmlRsaPemKey_ModulusIsNullOrEmpty_Test()
        {
            // Arrange                     
            var rsa = RSA.Create();
            rsa.KeySize = 2048;            // All empty values
            var expectedPrivateKeyXmlRsa = "<RSAKeyValue><Modulus></Modulus><Exponent></Exponent><P></P><Q></Q><DP></DP><DQ></DQ><InverseQ></InverseQ><D></D></RSAKeyValue>";

            // Act
            rsa.FromXmlRsaPemKey(expectedPrivateKeyXmlRsa);

            // Assert
            // Expected CryptographicException
        }
    }
}

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace com.tmobile.oss.security.taap.poptoken.builder
{
    public class PopTokenBuilderUtils
	{
		private static JsonWebTokenHandler _jsonWebTokenHandler;

		static PopTokenBuilderUtils()
		{
            _jsonWebTokenHandler = new JsonWebTokenHandler();
		}

        public static RsaSecurityKey CreateRsaSecurityKey(string rsaKeyPKCS8PemOrXml)
        {
            var rsa = RSA.Create();
            rsa.KeySize = 2048;

            if (rsaKeyPKCS8PemOrXml.Contains("BEGIN PUBLIC KEY"))
            {
                var pkcs8PrivateKeyArray = rsaKeyPKCS8PemOrXml.Split(Environment.NewLine);
                var pkcs8PrivateKeyBytes = Convert.FromBase64String(pkcs8PrivateKeyArray[1]);
                rsa.ImportSubjectPublicKeyInfo(pkcs8PrivateKeyBytes, out _);
            }
            else if (rsaKeyPKCS8PemOrXml.Contains("BEGIN PRIVATE KEY"))
            {
                var pkcs8PrivateKeyArray = rsaKeyPKCS8PemOrXml.Split(Environment.NewLine);
                var pkcs8PrivateKeyBytes = Convert.FromBase64String(pkcs8PrivateKeyArray[1]);
                rsa.ImportPkcs8PrivateKey(pkcs8PrivateKeyBytes, out _);
            }
            else if (rsaKeyPKCS8PemOrXml.Contains("<") &&
                     rsaKeyPKCS8PemOrXml.Contains(">"))
            {
                rsa.FromXmlRsaPemKey(rsaKeyPKCS8PemOrXml);
            }

            return new RsaSecurityKey(rsa);
        }

        public static TokenValidationResult ValidateToken(string popToken, string issuer, string audience, RsaSecurityKey rsaSecurityKey)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidIssuer = issuer,
                ValidAudiences = new[] { audience },
                IssuerSigningKeys = new[] { rsaSecurityKey }
            };
            
            return _jsonWebTokenHandler.ValidateToken(popToken, tokenValidationParameters);
        }
    }
}

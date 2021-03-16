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

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace com.tmobile.oss.security.taap.poptoken.builder
{
    public class PopTokenBuilderUtils
	{
		private static readonly JsonWebTokenHandler _jsonWebTokenHandler;

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

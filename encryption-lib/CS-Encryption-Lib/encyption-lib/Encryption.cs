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

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace com.tmobile.oss.security.taap.jwe
{
    /// <summary>
    /// Encryption
    /// </summary>
    public class Encryption : IEncryption
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public Encryption()
        {
        }

        /// <summary>
        /// Encrypt Async
        /// </summary>
        /// <param name="value">The value to encrypt as JWE string</param>
        /// <param name="keyResolver">Key Resolver</param>
        /// <param name="logger">Logger</param>
        /// <returns>JWE string</returns>
        public async Task<string> EncryptAsync(string value, IKeyResolver keyResolver, ILogger logger)
        {
            JsonWebKey jsonWebKey = null;

            try
            {
                jsonWebKey = await keyResolver.GetEncryptionKeyAsync();
                if (jsonWebKey == null)
                {
                    throw new EncryptionException(string.Format("Encryption key not found by KeyResolver."));
                }

                var encodedJwe = string.Empty;
                var extraHeaders = new Dictionary<string, object>
                {
                    { "kid", jsonWebKey.Kid },
                    { "kty", jsonWebKey.Kty }
                };
                if (jsonWebKey.Kty == "EC")
                {
                    var xByteArray = Jose.Base64Url.Decode(jsonWebKey.X);
                    var yByteArray = Jose.Base64Url.Decode(jsonWebKey.Y);
                    var eccKey = EccKey.New(xByteArray, yByteArray, null, CngKeyUsages.KeyAgreement);
                    encodedJwe = Jose.JWT.Encode(value, eccKey, Jose.JweAlgorithm.ECDH_ES_A256KW, Jose.JweEncryption.A256GCM, null, extraHeaders, null);
                }
                else if (jsonWebKey.Kty == "RSA")
                {
                    var keyParams = new RSAParameters
                    {
                        Exponent = Jose.Base64Url.Decode(jsonWebKey.E),
                        Modulus = Jose.Base64Url.Decode(jsonWebKey.N)
                    };
                    var rsa = RSA.Create();
                    rsa.ImportParameters(keyParams);
                    encodedJwe = Jose.JWT.Encode(value, rsa, Jose.JweAlgorithm.RSA_OAEP_256, Jose.JweEncryption.A256GCM, null, extraHeaders, null);
                }
                else
                {
                    throw new EncryptionException("Unsupport Json Web Key type.");
                }

                logger.LogDebug("Encrypting data with keyid: {0}, type: {1}, value: {2}", jsonWebKey.Kid, jsonWebKey.Kty, encodedJwe);

                return Constants.CIPHER_HEADER + encodedJwe;
            }
            catch (EncryptionException eeEx)
            {
                if (jsonWebKey == null)
                {
                    logger.LogError(eeEx, "An Encryption Exception Occurred: Value: {0}", value);
                }
                else
                {
                    logger.LogError(eeEx, "An Encryption Exception Occurred: Keyid: {0}, type: {1}", jsonWebKey.Kid, jsonWebKey.Kty);
                }

                throw;
            }
            catch (Exception ex)
            {
                if (ex.GetType() == typeof(NotImplementedException))
                {
                    throw;
                }
                else
                {
                    logger.LogError(ex, "An Exception Occurred: Keyid: {0}, type: {1}", jsonWebKey.Kid, jsonWebKey.Kty);
                    throw new EncryptionException("Unable to encrypt data.", ex);
                }
            }
        }

        /// <summary>
        /// Decrypt Async
        /// </summary>
        /// <param name="cipher">Cipher string</param>
        /// <param name="keyResolver">Key Resolver</param>
		/// <param name="logger">Logger</param>
        /// <returns>Descrypted string</returns>
        public async Task<string> DecryptAsync(string cipher, IKeyResolver keyResolver, ILogger logger)
        {
            var privateJsonWebKey = default(JsonWebKey);

            try
            {
                if (!cipher.StartsWith(Constants.CIPHER_HEADER, StringComparison.Ordinal))
                {
                    throw new InvalidHeaderException("Invalid encryption header.");
                }

                var value = default(string);

                cipher = cipher.Substring(Constants.CIPHER_HEADER.Length);
                var cipherArray = cipher.Split(new char[] { '.' });
                var json = Encoding.UTF8.GetString(Jose.Base64Url.Decode(cipherArray[0]));
                var requestedprivateJsonWebKey = new JsonWebKey(json);

                privateJsonWebKey = await keyResolver.GetDecryptionKeyAsync(requestedprivateJsonWebKey.Kid);
                if (privateJsonWebKey == null)
                {
                    throw new EncryptionException(string.Format("Decryption key not found. ID: '{0}'.", requestedprivateJsonWebKey.Kid));
                }

                if (privateJsonWebKey.Kty == "EC")
                {
                    var xByteArray = Jose.Base64Url.Decode(privateJsonWebKey.X);
                    var yByteArray = Jose.Base64Url.Decode(privateJsonWebKey.Y);
                    var dByteArray = Jose.Base64Url.Decode(privateJsonWebKey.D);
                    var privateKey = EccKey.New(xByteArray, yByteArray, dByteArray, CngKeyUsages.KeyAgreement);
                    value = Jose.JWT.Decode(cipher, privateKey);
                }
                else if (privateJsonWebKey.Kty == "RSA")
                {
                    var keyParams = new RSAParameters
                    {
                        Exponent = Jose.Base64Url.Decode(privateJsonWebKey.E),
                        Modulus = Jose.Base64Url.Decode(privateJsonWebKey.N),
                        P = Jose.Base64Url.Decode(privateJsonWebKey.P),
                        Q = Jose.Base64Url.Decode(privateJsonWebKey.Q),
                        D = Jose.Base64Url.Decode(privateJsonWebKey.D),
                        InverseQ = Jose.Base64Url.Decode(privateJsonWebKey.QI),
                        DP = Jose.Base64Url.Decode(privateJsonWebKey.DQ),
                        DQ = Jose.Base64Url.Decode(privateJsonWebKey.DP)
                    };

                    var rsa = RSA.Create();
                    rsa.ImportParameters(keyParams);
                    value = Jose.JWT.Decode(cipher, rsa, Jose.JweAlgorithm.RSA_OAEP_256, Jose.JweEncryption.A256GCM);
                }
                else
                {
                    throw new EncryptionException("Unsupport Json Web Key type.");
                }

                logger.LogDebug("Decrypted data with keyid: {0}, type: {1}, value: {2}", privateJsonWebKey.Kid, privateJsonWebKey.Kty, value);

                return value;
            }
            catch (InvalidHeaderException ihEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(ihEx, "An Invalid Header Exception Occurred: cipher: {0}", cipher);
                }
                else
                {
                    logger.LogError(ihEx, "An Invalid Header Exception Occurred: keyid: {0}, type: {1}, cipher: {2}", privateJsonWebKey.Kid, privateJsonWebKey.Kty, cipher);
                }

                throw;
            }
            catch (EncryptionException eEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(eEx, "An Decryption Exception Occurred: cipher: {0}", cipher);
                }
                else
                {
                    logger.LogError(eEx, "An Decryption Exception Occurred: Keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An Exception Occurred: Keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                throw new EncryptionException("Unable to decrypt data.", ex);
            }
        }
    }
}

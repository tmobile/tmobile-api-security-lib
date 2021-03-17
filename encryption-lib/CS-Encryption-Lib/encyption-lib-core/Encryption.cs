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

using Jose.keys;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
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
        IKeyResolver keyResolver;
        ILogger logger;

        /// <summary>
        /// Default constructor
        /// </summary>
        private Encryption()
        {
        }

        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="keyResolver">Key Resolver</param>
        /// <param name="logger">Logger</param>
        public Encryption(IKeyResolver keyResolver, ILogger logger) : this()
        {
            this.keyResolver = keyResolver;
            this.logger = logger;
        }

        /// <summary>
        /// Encrypt Async
        /// </summary>
        /// <param name="value">The value to encrypt as JWE string</param>
        /// <returns>JWE string</returns>
        public async Task<string> EncryptAsync(string value)
        {
            JsonWebKey publicJsonWebKey = null;

            try
            {
                publicJsonWebKey = await this.keyResolver.GetEncryptionKeyAsync();
                if (publicJsonWebKey == null)
                {
                    throw new EncryptionException(string.Format("Encryption key not found by KeyResolver."));
                }

                var encodedJwe = string.Empty;
                var extraHeaders = new Dictionary<string, object>
                {
                    { "kid", publicJsonWebKey.Kid },
                    { "kty", publicJsonWebKey.Kty }
                };
                if (publicJsonWebKey.Kty == "EC")
                {
                    var xByteArray = Jose.Base64Url.Decode(publicJsonWebKey.X);
                    var yByteArray = Jose.Base64Url.Decode(publicJsonWebKey.Y);
                    var eccKey = EccKey.New(xByteArray, yByteArray, null, CngKeyUsages.KeyAgreement);
                    encodedJwe = Jose.JWT.Encode(value, eccKey, Jose.JweAlgorithm.ECDH_ES_A256KW, Jose.JweEncryption.A256GCM, null, extraHeaders, null);
                }
                else if (publicJsonWebKey.Kty == "RSA")
                {
                    var keyParams = new RSAParameters
                    {
                        Exponent = Jose.Base64Url.Decode(publicJsonWebKey.E),
                        Modulus = Jose.Base64Url.Decode(publicJsonWebKey.N)
                    };
                    var rsa = RSA.Create();
                    rsa.ImportParameters(keyParams);
                    encodedJwe = Jose.JWT.Encode(value, rsa, Jose.JweAlgorithm.RSA_OAEP_256, Jose.JweEncryption.A256GCM, null, extraHeaders, null);
                }
                else
                {
                    throw new EncryptionException("Unsupport Json Web Key type.");
                }

                logger.LogDebug("Encrypting data with keyid: {0}, type: {1}", publicJsonWebKey.Kid, publicJsonWebKey.Kty);

                return Constants.CIPHER_HEADER + encodedJwe;
            }
            catch (Jose.EncryptionException iaEx)
            {
                if (publicJsonWebKey == null)
                {
                    logger.LogError(iaEx, "An Encryption Exceptionn occurred.");
                }
                else
                {
                    logger.LogError(iaEx, "An Encryption Exceptionn occurred. keyid: {0}, type: {1}", publicJsonWebKey.Kid, publicJsonWebKey.Kty);
                }

                throw new EncryptionException("Unable to decrypt data.", iaEx);
            }
            catch (Jose.InvalidAlgorithmException iaEx)
            {
                if (publicJsonWebKey == null)
                {
                    logger.LogError(iaEx, "An Invalid Algorithm Exception occurred.");
                }
                else
                {
                    logger.LogError(iaEx, "An Invalid Algorithm Exception occurred. keyid: {0}, type: {1}", publicJsonWebKey.Kid, publicJsonWebKey.Kty);
                }

                throw new EncryptionException("Unable to decrypt data.", iaEx);
            }
            catch (EncryptionException eeEx)
            {
                if (publicJsonWebKey == null)
                {
                    logger.LogError(eeEx, "An Encryption Exception Occurred: Value: {0}", value);
                }
                else
                {
                    logger.LogError(eeEx, "An Encryption Exception Occurred: Keyid: {0}, type: {1}", publicJsonWebKey.Kid, publicJsonWebKey.Kty);
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
                    logger.LogError(ex, "An Exception Occurred: Keyid: {0}, type: {1}", publicJsonWebKey.Kid, publicJsonWebKey.Kty);
                    throw new EncryptionException("Unable to encrypt data.", ex);
                }
            }
        }

        /// <summary>
        /// Decrypt Async
        /// </summary>
        /// <param name="cipher">Cipher string</param>
        /// <returns>Descrypted string</returns>
        public async Task<string> DecryptAsync(string cipher)
        {
            var privateJsonWebKey = default(JsonWebKey);

            try
            {
                if (string.IsNullOrEmpty(cipher) ||
                   !cipher.StartsWith(Constants.CIPHER_HEADER, StringComparison.Ordinal))
                {
                    throw new InvalidHeaderException("Invalid encryption header.");
                }

                var value = default(string);
                var requestedprivateJsonWebKey = default(JsonWebKey);
                try
                {
                    cipher = cipher.Substring(Constants.CIPHER_HEADER.Length);
                    var cipherArray = cipher.Split(new char[] { '.' });
                    var json = Encoding.UTF8.GetString(Jose.Base64Url.Decode(cipherArray[0]));
                    requestedprivateJsonWebKey = new JsonWebKey(json);
                }
                catch(ArgumentNullException anEx)
                {
                    throw new SerializerException("Unable to deserializer value.", anEx);
                }
                catch (ArgumentException aEx)
                {
                    throw new SerializerException("Unable to deserializer value.", aEx);
                }

                privateJsonWebKey = await this.keyResolver.GetDecryptionKeyAsync(requestedprivateJsonWebKey.Kid);
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
            catch(Jose.EncryptionException iaEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(iaEx, "An Encryption Exceptionn occurred.");
                }
                else
                {
                    logger.LogError(iaEx, "An Encryption Exceptionn occurred. keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw new EncryptionException("Unable to decrypt data.", iaEx);
            }
            catch (Jose.InvalidAlgorithmException iaEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(iaEx, "An Invalid Algorithm Exception occurred.");
                }
                else
                {
                    logger.LogError(iaEx, "An Invalid Algorithm Exception occurred. keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw new EncryptionException("Unable to decrypt data.", iaEx);
            }
            catch (InvalidHeaderException ihEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(ihEx, "An Invalid Header Exception occurred.");
                }
                else
                {
                    logger.LogError(ihEx, "An Invalid Header Exception occurred. keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw;
            }
            catch (SerializerException sEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(sEx.InnerException, "Unable to deserializer value.");
                }
                else
                {
                    logger.LogError(sEx, "Unable to deserializer value.: Keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw;
            }
            catch (EncryptionException eEx)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(eEx, "An Decryption Exception Occurred");
                }
                else
                {
                    logger.LogError(eEx, "An Decryption Exception Occurred: Keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw;
            }
            catch (Exception ex)
            {
                if (privateJsonWebKey == null)
                {
                    logger.LogError(ex, "An Decryption Exception Occurred");
                }
                else
                {
                    logger.LogError(ex, "An Exception Occurred: Keyid: {0}, type: {1}", privateJsonWebKey.Kid, privateJsonWebKey.Kty);
                }

                throw new EncryptionException("Unable to decrypt data.", ex);
            }
        }
    }
}

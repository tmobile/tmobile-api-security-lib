/*
 * Copyright 2019 T-Mobile US, Inc.
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

package com.tmobile.oss.security.taap.poptoken.builder.utils;

import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import com.tmobile.oss.security.taap.poptoken.builder.exception.PopPrivateKeyParseException;

/**
 * Provides the helper methods for building the PoP token.
 */
public class PopTokenBuilderUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected static final String PKCS_1_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----";
    protected static final String PKCS_1_PRIVATE_KEY_SUFFIX = "-----END RSA PRIVATE KEY-----";

    protected static final String PKCS_8_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";
    protected static final String PKCS_8_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

    protected static final String PKCS_8_ENCRYPTED_PRIVATE_KEY_PREFIX = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    protected static final String PKCS_8_ENCRYPTED_PRIVATE_KEY_SUFFIX = "-----END ENCRYPTED PRIVATE KEY-----";

    /**
     * Converts the private key PEM string to RSAPrivateKey
     * 
     * @param privateKeyPemString The private key PEM string
     * @return The RSAPrivateKey
     * @throws PopPrivateKeyParseException If privateKeyPemString cannot be parsed or cannot be converted to RSAPrivateKey
     * @throws IllegalArgumentException If privateKeyPemString is null or empty
     */
    public static RSAPrivateKey keyPemStringToRsaPrivateKey(String privateKeyPemString) throws PopPrivateKeyParseException {

        if (StringUtils.isBlank(privateKeyPemString)) {
            throw new IllegalArgumentException("The privateKeyPemString should not be null or empty");
        }
        try {
            if (privateKeyPemString.startsWith(PKCS_8_PRIVATE_KEY_PREFIX) && privateKeyPemString.contains(PKCS_8_PRIVATE_KEY_SUFFIX)) {

                privateKeyPemString = privateKeyPemString.substring(PKCS_8_PRIVATE_KEY_PREFIX.length(),
                        privateKeyPemString.indexOf(PKCS_8_PRIVATE_KEY_SUFFIX));
                privateKeyPemString = sanitizePrivateKeyPemString(privateKeyPemString);

                byte[] keyBytes = toBase64DecodedBytes(privateKeyPemString);
                return buildRsaPrivateKey(keyBytes);

            } else {
                throw new PopPrivateKeyParseException(
                        "The privateKeyPemString contains unsupported format, only PKCS#8 format is currently supported");
            }
        } catch (PopPrivateKeyParseException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PopPrivateKeyParseException(
                    "Error occurred while converting privateKeyPemString to RSAPrivateKey, error: " + ex.toString(), ex);
        }
    }

    /**
     * Converts the encrypted private key PEM string to RSAPrivateKey
     * 
     * @param encryptedPrivateKeyPemString The encrypted private key PEM string
     * @param privateKeyPassword The private key password
     * @return The RSAPrivateKey
     * @throws PopPrivateKeyParseException If encryptedPrivateKeyPemString cannot be parsed or cannot be converted to RSAPrivateKey
     * @throws IllegalArgumentException If encryptedPrivateKeyPemString is null or empty
     */
    public static RSAPrivateKey encryptedKeyPemStringToRsaPrivateKey(String encryptedPrivateKeyPemString, String privateKeyPassword)
            throws PopPrivateKeyParseException {

        if (StringUtils.isBlank(encryptedPrivateKeyPemString)) {
            throw new IllegalArgumentException("The encryptedPrivateKeyPemString should not be null or empty");
        }
        if (StringUtils.isBlank(privateKeyPassword)) {
            throw new IllegalArgumentException("The privateKeyPassword should not be null or empty");
        }
        try {
            if (encryptedPrivateKeyPemString.startsWith(PKCS_8_ENCRYPTED_PRIVATE_KEY_PREFIX)
                    && encryptedPrivateKeyPemString.contains(PKCS_8_ENCRYPTED_PRIVATE_KEY_SUFFIX)) {
                return buildRsaPrivateKey(encryptedPrivateKeyPemString, privateKeyPassword);
            } else {
                throw new PopPrivateKeyParseException(
                        "The encryptedPrivateKeyPemString contains unsupported format, only PKCS#8 format is currently supported");
            }
        } catch (PopPrivateKeyParseException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PopPrivateKeyParseException(
                    "Error occurred while converting encryptedPrivateKeyPemString to RSAPrivateKey, error: " + ex.toString(), ex);
        }
    }

    // ===== helper methods ===== //

    /**
     * Builds the RSAPrivateKey using the specified PKCS8 private key bytes
     * 
     * @param privateKeyBytes The PKCS8 private key bytes
     * @return The RSA private key
     * @throws GeneralSecurityException If error occurs while creating the RSA private key
     */
    private static RSAPrivateKey buildRsaPrivateKey(byte[] privateKeyBytes) throws GeneralSecurityException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) rsaKeyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    /**
     * Builds the RSAPrivateKey using the specified PKCS8 encrypted private key bytes and privateKeyPassword
     * 
     * @param encryptedPrivateKeyPemString The encrypted PKCS8 private key PEM string
     * @param privateKeyPassword The private key password
     * @return The RSA private key
     * @throws OperatorCreationException If InputDecryptorProvider cannot be built
     * @throws PKCSException If private key cannot be decrypted
     * @throws IOException If PEM string cannot be parsed
     */
    private static RSAPrivateKey buildRsaPrivateKey(String encryptedPrivateKeyPemString, String privateKeyPassword)
            throws OperatorCreationException, PKCSException, IOException {

        PEMParser pemParser = null;
        try {
            pemParser = new PEMParser(new StringReader(encryptedPrivateKeyPemString));
            PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            InputDecryptorProvider decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .build(privateKeyPassword.toCharArray());
            PrivateKeyInfo privateKeyInfo = pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptionProv);
            return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
        } finally {
            if (pemParser != null) {
                pemParser.close();
            }
        }
    }

    /**
     * Sanitizes the private key PEM string by removing the line separators.
     * 
     * @param privateKeyPemString The private key PEM string
     * @return The sanitized PEM string
     */
    private static String sanitizePrivateKeyPemString(String privateKeyPemString) {
        return privateKeyPemString.replace(System.getProperty("line.separator"), "");
    }

    /**
     * Converts the private key PEM string to base64 decoded bytes.
     * 
     * @param privateKeyPemString The private key PEM file string
     * @return The base64 decoded bytes.
     */
    private static byte[] toBase64DecodedBytes(String privateKeyPemString) {
        return Base64.decodeBase64(privateKeyPemString);
    }
}

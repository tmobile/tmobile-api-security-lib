package com.tmobile.oss.security.taap.poptoken.validator.utils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwk.Jwk;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopPublicKeyParseException;

/**
 * Provides the helper methods for the PoP token validation.
 */
public class PopTokenValidatorUtils {

    @SuppressWarnings("unused")
    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorUtils.class);

    protected static final String RSA_ENCRYPTION_ALGORITHM_IDENTIFIER = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A";

    protected static final String X509_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";
    protected static final String X509_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

    protected static final String PKCS_1_PUBLIC_KEY_PREFIX = "-----BEGIN RSA PUBLIC KEY-----";
    protected static final String PKCS_1_PUBLIC_KEY_SUFFIX = "-----END RSA PUBLIC KEY-----";

    private static ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Converts the public key PEM string to RSAPublicKey.
     * 
     * @param publicKeyPemString The public key PEM string
     * @return The RSAPublicKey
     * @throws PopPublicKeyParseException If the publicKeyPemString cannot be parsed or cannot be converted to RSAPublicKey
     * @throws IllegalArgumentException If the publicKeyPemString is null or empty
     */
    public static RSAPublicKey keyPemStringToRsaPublicKey(String publicKeyPemString) throws PopPublicKeyParseException {

        if (StringUtils.isBlank(publicKeyPemString)) {
            throw new IllegalArgumentException("The publicKeyPemString should not be null or empty");
        }

        try {
            if (publicKeyPemString.startsWith(X509_PUBLIC_KEY_PREFIX) && publicKeyPemString.contains(X509_PUBLIC_KEY_SUFFIX)) {

                publicKeyPemString = publicKeyPemString.substring(X509_PUBLIC_KEY_PREFIX.length(),
                        publicKeyPemString.indexOf(X509_PUBLIC_KEY_SUFFIX));
                publicKeyPemString = sanitizePublicKeyPemString(publicKeyPemString);
                byte[] keyBytes = toBase64DecodedBytes(publicKeyPemString);
                return (RSAPublicKey) buildPublicKeyFromX509KeyBytes(keyBytes);

            } else if (publicKeyPemString.startsWith(PKCS_1_PUBLIC_KEY_PREFIX)
                    && publicKeyPemString.contains(PKCS_1_PUBLIC_KEY_SUFFIX)) {

                publicKeyPemString = publicKeyPemString.substring(PKCS_1_PUBLIC_KEY_PREFIX.length(),
                        publicKeyPemString.indexOf(PKCS_1_PUBLIC_KEY_SUFFIX));
                // add the RSA_ENCRYPTION_ALGORITHM_IDENTIFIER to convert it to PKCS#8
                publicKeyPemString = RSA_ENCRYPTION_ALGORITHM_IDENTIFIER + publicKeyPemString;
                byte[] keyBytes = toBase64DecodedBytes(publicKeyPemString);
                return (RSAPublicKey) buildPublicKeyFromX509KeyBytes(keyBytes);

            } else {
                throw new PopPublicKeyParseException("The publicKeyPemString contains unsupported format");
            }
        } catch (PopPublicKeyParseException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PopPublicKeyParseException(
                    "Error occurred while converting publicKeyPemString to RSAPublicKey, error: " + ex.toString(), ex);
        }
    }

    /**
     * Converts the JWK string to RSAPublicKey.
     * 
     * @param jwkString The public key PEM string
     * @return The RSAPublicKey
     * @throws PopPublicKeyParseException If the jwkString cannot be parsed or cannot be converted to RSAPublicKey
     * @throws IllegalArgumentException If the jwkString is null or empty
     */
    public static RSAPublicKey jwkStringToRsaPublicKey(String jwkString) throws PopPublicKeyParseException {

        if (StringUtils.isBlank(jwkString)) {
            throw new IllegalArgumentException("The jwkString should not be null or empty");
        }

        try {
            TypeReference<HashMap<String, Object>> typeRef = new TypeReference<HashMap<String, Object>>() {
            };
            HashMap<String, Object> jwkMap = objectMapper.readValue(jwkString, typeRef);
            Jwk jwk = Jwk.fromValues(jwkMap);
            return (RSAPublicKey) jwk.getPublicKey();
        } catch (Exception ex) {
            throw new PopPublicKeyParseException("Error occurred while converting jwkString to RSAPublicKey, error: " + ex.toString(),
                    ex);
        }
    }

    /**
     * Creates SHA 256 base64 url encrypted hash of the specified string.
     * 
     * @param stringToHash The string to be hashed
     * @return SHA 256 base64 encrypted hash.
     */
    public static String sha256Base64UrlSafe(String stringToHash) {
        byte[] sha256Digest = DigestUtils.sha256(stringToHash);
        return Base64.encodeBase64URLSafeString(sha256Digest);
    }

    // ===== helper methods ===== //

    /**
     * Builds the PublicKey from X509 public key bytes
     * 
     * @param publicKeyBytes The X509 public key bytes
     * @return The PublicKey
     * @throws NoSuchAlgorithmException If algorithm is not found
     * @throws InvalidKeySpecException If key specification is invalid
     */
    private static PublicKey buildPublicKeyFromX509KeyBytes(byte[] publicKeyBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }

    /**
     * Sanitizes the public PEM string by removing the line separators.
     * 
     * @param publicKeyPemString The public key PEM file string
     * @return The sanitized PEM string
     */
    private static String sanitizePublicKeyPemString(String publicKeyPemString) {
        return publicKeyPemString.replace(System.getProperty("line.separator"), "");
    }

    /**
     * Converts the public key PEM string to base64 decoded bytes.
     * 
     * @param publicKeyPemString The public key PEM file string
     * @return The base64 decoded bytes.
     */
    private static byte[] toBase64DecodedBytes(String publicKeyPemString) {
        return Base64.decodeBase64(publicKeyPemString);
    }
}

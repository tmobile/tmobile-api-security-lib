package com.tmobile.oss.security.taap.poptoken.builder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;
import com.tmobile.oss.security.taap.poptoken.builder.utils.PopTokenBuilderUtils;

/**
 * A builder class to build the PoP token.
 * 
 * PopTokenBuilder is not thread-safe so the instance of this class should not be shared between multiple threads.
 */
public class PopTokenBuilder {

    protected static final int POP_TOKEN_VALIDITY_DURATION_IN_MILLIS = 2 * 60 * 1000;
    protected static final int MAX_NUMBER_OF_EHTS = 100;

    private RSAPrivateKey rsaPrivateKey;
    private String rsaPrivateKeyPemString;
    private String privateKeyPassword;
    private LinkedHashMap<String, String> ehtsKeyValueMap;

    /**
     * Returns the new instance of PopTokenBuilder.
     * 
     * @return The new instance of PopTokenBuilder
     */
    public static PopTokenBuilder newInstance() {
        return new PopTokenBuilder();
    }

    /**
     * Sets the ehtsKeyValueMap, this LinkedHashMap will be used to calculate the values of ehts (external headers to sign) and edts
     * (hash of external data to sign).
     * 
     * @param ehtsKeyValueMap The map containing the values for all the ehts (external headers to sign) keys.
     *            <p>
     *            Determining the ehts key name:
     *            <ul>
     *            <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     *            For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     *            "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     *            "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     *            of "uri" ehts should not be in URL encoded format.</li>
     *            <li>For HTTP method, "http-method" should be used as ehts key
     *            name,<code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     *            <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     *            <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     *            </ul>
     * @return The PopTokenBuilder
     */
    public PopTokenBuilder setEhtsKeyValueMap(LinkedHashMap<String, String> ehtsKeyValueMap) {
        this.ehtsKeyValueMap = ehtsKeyValueMap;
        return this;
    }

    /**
     * Signs the PoP token using the specified rsaPrivateKeyPemString.
     * 
     * @param rsaPrivateKeyPemString The RSA private key PEM string
     * @return The PopTokenBuilder
     */
    public PopTokenBuilder signWith(String rsaPrivateKeyPemString) {
        this.rsaPrivateKeyPemString = rsaPrivateKeyPemString;
        return this;
    }

    /**
     * Signs the PoP token using the specified encryptedRsaPrivateKeyPemString and uses the privateKeyPassword to decrypt the private
     * key PEM string string.
     * 
     * @param encryptedRsaPrivateKeyPemString The encrypted RSA private key PEM string
     * @param privateKeyPassword The RSA private key password
     * @return The PopTokenBuilder
     */
    public PopTokenBuilder signWith(String encryptedRsaPrivateKeyPemString, String privateKeyPassword) {
        this.rsaPrivateKeyPemString = encryptedRsaPrivateKeyPemString;
        this.privateKeyPassword = privateKeyPassword;
        return this;
    }

    /**
     * Signs the PoP token using the specified RSAPrivateKey.
     * 
     * @param rsaPrivateKey The RSA private key
     * @return The PopTokenBuilder
     */
    public PopTokenBuilder signWith(RSAPrivateKey rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
        return this;
    }

    /**
     * Returns the issued at time.
     * <p>
     * Note: This method is having the default access for JUnit tests to override it by creating a sub class of PopTokenBuilder.
     * 
     * @return The issued at time
     */
    Date getIssuedAt() {
        return new Date();
    }

    /**
     * Returns the expiration time.
     * 
     * @param issuedAt The time when the PoP token is issued
     * @return The expiration time
     */
    protected Date getExpiration(Date issuedAt) {
        return new Date(issuedAt.getTime() + POP_TOKEN_VALIDITY_DURATION_IN_MILLIS);
    }

    /**
     * Returns the version.
     * 
     * @return The version
     */
    protected String getVersion() {
        return "1";
    }

    /**
     * Returns the unique identifier.
     * 
     * @return The unique identifier
     */
    protected String getUniqueIdentifier() {
        return UUID.randomUUID().toString();
    }

    /**
     * Builds, signs and returns the string representation of the PoP token. The PoP token will be valid for 2 minutes.
     * 
     * @return The PoP token
     * @throws PopTokenBuilderException if error occurs while building the PoP token
     */
    public String build() throws PopTokenBuilderException {

        try {
            if (ehtsKeyValueMap == null || ehtsKeyValueMap.isEmpty() || doesContainAnyEmptyKeysOrValues(ehtsKeyValueMap)) {
                throw new PopTokenBuilderException(
                        "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values");
            }

            if (ehtsKeyValueMap.size() > 100) {
                throw new PopTokenBuilderException(
                        "The ehtsKeyValueMap should not contain more than " + MAX_NUMBER_OF_EHTS + " entries");
            }

            if (rsaPrivateKey == null && StringUtils.isBlank(rsaPrivateKeyPemString)) {
                throw new PopTokenBuilderException(
                        "Either rsaPrivateKey or rsaPrivateKeyPemString should be provided to sign the PoP token");
            }

            if (rsaPrivateKey != null && StringUtils.isNotBlank(rsaPrivateKeyPemString)) {
                throw new PopTokenBuilderException(
                        "Either only rsaPrivateKey or only rsaPrivateKeyPemString should be provided to sign the PoP token");
            }

            if (rsaPrivateKey == null) {
                if (privateKeyPassword != null) {
                    rsaPrivateKey = PopTokenBuilderUtils.encryptedKeyPemStringToRsaPrivateKey(rsaPrivateKeyPemString,
                            privateKeyPassword);
                } else {
                    rsaPrivateKey = PopTokenBuilderUtils.keyPemStringToRsaPrivateKey(rsaPrivateKeyPemString);
                }
            }

            Date issuedAt = getIssuedAt();

            return JWT.create() //
                    .withClaim("ehts", buildEhtsString(ehtsKeyValueMap)) //
                    .withClaim("edts", calculateEdtsSha256Base64Hash(ehtsKeyValueMap)) //
                    .withClaim("jti", getUniqueIdentifier()) //
                    .withClaim("v", getVersion()) //
                    .withIssuedAt(issuedAt) //
                    .withExpiresAt(getExpiration(issuedAt)) //
                    .sign(buildRsa256Algorithm(rsaPrivateKey, null)); //

        } catch (PopTokenBuilderException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PopTokenBuilderException("Error occurred while building the PoP token, error: " + ex.toString(), ex);
        }
    }

    // ===== helper methods ===== //

    /**
     * Returns true if the ehtsKeyValueMap contains any empty keys
     * 
     * @param ehtsKeyValueMap
     * @return
     */
    private boolean doesContainAnyEmptyKeysOrValues(LinkedHashMap<String, String> ehtsKeyValueMap) {
        for (Entry<String, String> ehtsKeyValueEntry : ehtsKeyValueMap.entrySet()) {
            if (StringUtils.isBlank(ehtsKeyValueEntry.getKey()) || StringUtils.isBlank(ehtsKeyValueEntry.getValue())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the semicolon separated ehts string using the specified ehtsKeysList
     * 
     * @param ehtsKeyValueMap The ehts keys list
     * @return the ehts string containing the semicolon delimited ehts keys
     */
    private String buildEhtsString(LinkedHashMap<String, String> ehtsKeyValueMap) {

        StringBuilder ehtsStringBuilder = new StringBuilder();
        for (String ehtsKey : ehtsKeyValueMap.keySet()) {
            if (ehtsStringBuilder.length() > 0) {
                ehtsStringBuilder.append(";");
            }
            ehtsStringBuilder.append(ehtsKey);
        }
        return ehtsStringBuilder.toString();
    }

    /**
     * Calculates the edts (hash of external data to sign) in the same sequence as provided in the LinkedHashMap.
     * 
     * @param ehtsKeysList
     * @param ehtsKeyValueMap
     * @return The edts (hash of external data to sign)
     */
    private String calculateEdtsSha256Base64Hash(Map<String, String> ehtsKeyValueMap) {
        StringBuilder stringToHashBuilder = new StringBuilder();
        for (Entry<String, String> ehtsKeyValueEntry : ehtsKeyValueMap.entrySet()) {
            stringToHashBuilder.append(ehtsKeyValueEntry.getValue());
        }
        String stringToHash = stringToHashBuilder.toString();
        return sha256Base64UrlSafeString(stringToHash);
    }

    /**
     * Creates SHA 256 base64 URL safe encrypted hash of the specified string.
     * 
     * @param stringToHash The string to be hashed
     * @return SHA 256 base64 encrypted hash.
     */
    private String sha256Base64UrlSafeString(String stringToHash) {
        byte[] sha256Digest = DigestUtils.sha256(stringToHash);
        return Base64.encodeBase64URLSafeString(sha256Digest);
    }

    /**
     * Builds the RSA 256 algorithm.
     * 
     * @param rsaPrivateKey The RSA private key
     * @param privateKeyId The private key ID
     * @return The RSA 256 algorithm
     */
    private Algorithm buildRsa256Algorithm(RSAPrivateKey rsaPrivateKey, String privateKeyId) {
        Algorithm algorithm = Algorithm.RSA256(new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                throw new NotImplementedException("The method getPublicKeyById is not implemented");
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return rsaPrivateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return privateKeyId;
            }
        });
        return algorithm;
    }
}

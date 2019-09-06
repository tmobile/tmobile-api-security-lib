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

package com.tmobile.oss.security.taap.poptoken.validator;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.tmobile.oss.security.taap.poptoken.validator.exception.InvalidPopTokenException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenExpiredException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenInvalidEdtsHashException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenSignatureVerificationException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenValidatorException;
import com.tmobile.oss.security.taap.poptoken.validator.utils.PopTokenValidatorUtils;

/**
 * A helper class for validating the PoP token.
 */
public class PopTokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidator.class);

    private static final long ACCEPTED_LEEWAY_SECONDS = 10;

    /**
     * Returns the new instance of PopTokenValidator.
     * 
     * @return The new instance of PopTokenValidator
     */
    public static PopTokenValidator newInstance() {
        return new PopTokenValidator();
    }

    /**
     * Validates the PoP token with public key PEM string.
     * 
     * @param popToken The PoP token string
     * @param publicKeyPemString The public key PEM string to verify the PoP token signature
     * @param ehtsKeyValueMap The map containing the values for all the ehts (external headers to sign) keys.
     *            <p>
     *            Determining the ehts key name:
     *            <ul>
     *            <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     *            For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     *            "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     *            "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     *            of "uri" ehts should not be in URL encoded format.</li>
     *            <li>For HTTP method, "http-method" should be used as ehts key name,
     *            <code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     *            <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     *            <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     *            </ul>
     *            <p>
     * @throws IllegalArgumentException If the popToken is null or empty, <br>
     *             publicKeyPemString is null or empty or ehtsKeyValueMap is invalid
     * @throws InvalidPopTokenException If the PoP token is invalid and so cannot be decoded
     * @throws PopTokenExpiredException If the PoP token is expired
     * @throws PopTokenSignatureVerificationException If the PoP token signature resulted invalid
     * @throws PopTokenInvalidEdtsHashException If the edts (external data to sign) hash is invalid
     * @throws PopTokenValidatorException If the PoP token cannot be validated
     */
    public void validatePopTokenWithPublicKeyPemString(String popToken, String publicKeyPemString, Map<String, String> ehtsKeyValueMap)
            throws PopTokenValidatorException {

        if (StringUtils.isBlank(popToken)) {
            throw new IllegalArgumentException("The popToken should not be null or empty");
        }
        if (StringUtils.isBlank(publicKeyPemString)) {
            throw new IllegalArgumentException("The publicKeyPemString should not be null or empty");
        }
        if (ehtsKeyValueMap == null || ehtsKeyValueMap.isEmpty() || doesContainAnyEmptyKeysOrValues(ehtsKeyValueMap)) {
            throw new IllegalArgumentException(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values");
        }

        RSAPublicKey rsaPublicKey = PopTokenValidatorUtils.keyPemStringToRsaPublicKey(publicKeyPemString);
        validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
    }

    /**
     * Validates the PoP token with public key JWK string.
     * 
     * @param popToken The PoP token string
     * @param publicKeyJwkString The public key JWK string to verify the PoP token signature
     * @param ehtsKeyValueMap The map containing the values for all the ehts (external headers to sign) keys.
     *            <p>
     *            Determining the ehts key name:
     *            <ul>
     *            <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     *            For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     *            "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     *            "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     *            of "uri" ehts should not be in URL encoded format.</li>
     *            <li>For HTTP method, "http-method" should be used as ehts key name,
     *            <code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     *            <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     *            <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     *            </ul>
     *            <p>
     * @throws IllegalArgumentException If the popToken is null or empty, <br>
     *             publicKeyJwkString is null or empty or ehtsKeyValueMap is invalid
     * @throws InvalidPopTokenException If the PoP token is invalid and so cannot be decoded
     * @throws PopTokenExpiredException If the PoP token is expired
     * @throws PopTokenSignatureVerificationException If the PoP token signature resulted invalid
     * @throws PopTokenInvalidEdtsHashException If the edts (external data to sign) hash is invalid
     * @throws PopTokenValidatorException If the PoP token cannot be validated
     */
    public void validatePopTokenWithPublicKeyJwkString(String popToken, String publicKeyJwkString, Map<String, String> ehtsKeyValueMap)
            throws PopTokenValidatorException {
        
        if (StringUtils.isBlank(popToken)) {
            throw new IllegalArgumentException("The popToken should not be null or empty");
        }
        if (StringUtils.isBlank(publicKeyJwkString)) {
            throw new IllegalArgumentException("The publicKeyJwkString should not be null or empty");
        }
        if (ehtsKeyValueMap == null || ehtsKeyValueMap.isEmpty() || doesContainAnyEmptyKeysOrValues(ehtsKeyValueMap)) {
            throw new IllegalArgumentException(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values");
        }
        
        RSAPublicKey rsaPublicKey = PopTokenValidatorUtils.jwkStringToRsaPublicKey(publicKeyJwkString);
        validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
    }

    /**
     * Validates the PoP token with RSA public key.
     * 
     * @param popToken The PoP token string
     * @param rsaPublicKey The RSAPublicKey to verify the PoP token signature
     * @param ehtsKeyValueMap The map containing the values for all the ehts (external headers to sign) keys.
     *            <p>
     *            Determining the ehts key name:
     *            <ul>
     *            <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     *            For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     *            "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     *            "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     *            of "uri" ehts should not be in URL encoded format.</li>
     *            <li>For HTTP method, "http-method" should be used as ehts key name,
     *            <code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     *            <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     *            <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     *            </ul>
     *            <p>
     * @throws IllegalArgumentException If the popToken is null or empty, rsaPublicKey is null or ehtsKeyValueMap is invalid
     * @throws InvalidPopTokenException If the PoP token is invalid and so cannot be decoded
     * @throws PopTokenExpiredException If the PoP token is expired
     * @throws PopTokenSignatureVerificationException If the PoP token signature resulted invalid
     * @throws PopTokenInvalidEdtsHashException If the edts (external data to sign) hash is invalid
     * @throws PopTokenValidatorException If the PoP token cannot be validated
     */
    public void validatePopTokenWithRsaPublicKey(String popToken, RSAPublicKey rsaPublicKey, Map<String, String> ehtsKeyValueMap)
            throws PopTokenValidatorException {

        if (StringUtils.isBlank(popToken)) {
            throw new IllegalArgumentException("The popToken should not be null or empty");
        }
        if (rsaPublicKey == null) {
            throw new IllegalArgumentException("The rsaPublicKey should not be null");
        }
        if (ehtsKeyValueMap == null || ehtsKeyValueMap.isEmpty() || doesContainAnyEmptyKeysOrValues(ehtsKeyValueMap)) {
            throw new IllegalArgumentException(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values");
        }

        try {
            DecodedJWT decodedJwt = validateTokenUsingJwtVerifier(popToken, rsaPublicKey);
            validateEdtsHash(decodedJwt, ehtsKeyValueMap);
        } catch (PopTokenValidatorException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PopTokenValidatorException("Error occurred while validating the PoP token, error: " + ex.toString(), ex);
        }
    }

    /**
     * Gets the list of ehts (external header to sign) keys from PoP token.
     * 
     * @param popToken The PoP token
     * @return The list of ehts (external header to sign) keys
     * @throws InvalidPopTokenException If an error occurs while retrieving the ehts keys from PoP token
     * @throws IllegalArgumentException If the popToken is null or empty, rsaPublicKey is null or ehtsKeyValueMap is invalid
     */
    public List<String> getEhtsKeys(String popToken) throws InvalidPopTokenException {

        if (StringUtils.isBlank(popToken)) {
            throw new IllegalArgumentException("The popToken should not be null or empty");
        }

        try {
            DecodedJWT decodedJwt = JWT.decode(popToken);
            return getEhts(decodedJwt);
        } catch (Exception ex) {
            throw new InvalidPopTokenException("Error occurred while parsing the PoP token, error: " + ex.toString(), ex);
        }
    }

    /**
     * Returns the accepted leeway in seconds.
     * 
     * Note: This method can be overridden to modify the default accepted leeway in seconds which is 10 seconds.
     * 
     * @return The accepted leeway in seconds.
     */
    protected long getAcceptedLeewaySeconds() {
        return ACCEPTED_LEEWAY_SECONDS;
    }

    // ===== helper methods ===== //

    /**
     * Returns true if the ehtsKeyValueMap contains any empty keys
     * 
     * @param ehtsKeyValueMap
     * @return
     */
    private boolean doesContainAnyEmptyKeysOrValues(Map<String, String> ehtsKeyValueMap) {
        for (Entry<String, String> ehtsKeyValueEntry : ehtsKeyValueMap.entrySet()) {
            if (StringUtils.isBlank(ehtsKeyValueEntry.getKey()) || StringUtils.isBlank(ehtsKeyValueEntry.getValue())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validates the PoP token using JWTVerifier
     * 
     * @param popToken The PoP token string
     * @param rsaPublicKey The RSAPublicKey to verify the signature of PoP token
     * @return The decoded JWT token
     * @throws InvalidPopTokenException If the PoP token is invalid and so cannot be decoded
     * @throws PopTokenExpiredException If the PoP token is expired
     * @throws PopTokeSignatureVerificationException If the PoP token signature resulted invalid
     * @throws PopTokenValidatorException If the PoP token cannot be validated
     */
    private DecodedJWT validateTokenUsingJwtVerifier(String popToken, RSAPublicKey rsaPublicKey) throws PopTokenValidatorException {

        RSAKeyProvider rsaKeyProvider = buildRsaKeyProvider(rsaPublicKey);
        Algorithm algorithm = Algorithm.RSA256(rsaKeyProvider);
        JWTVerifier jwtVerifier = //
                JWT.require(algorithm) //
                        .acceptLeeway(getAcceptedLeewaySeconds()) //
                        .build(); //
        try {
            return jwtVerifier.verify(popToken);
        } catch (JWTDecodeException ex) {
            throw new InvalidPopTokenException("Couldn't decode the token, error: " + ex.toString(), ex);
        } catch (TokenExpiredException ex) {
            throw new PopTokenExpiredException("The token has expired, currentServerTime: " + new Date() + ", error: " + ex.toString(),
                    ex);
        } catch (SignatureVerificationException ex) {
            throw new PopTokenSignatureVerificationException("Couldn't verify the signature, error: " + ex.toString(), ex);
        } catch (Exception ex) {
            throw new PopTokenValidatorException("Error occurred while validating the PoP token, error: " + ex.toString(), ex);
        }
    }

    /**
     * Builds the RSA key provider
     * 
     * @param rsaPublicKey The RSA public key
     * @return The RSA key provider
     */
    private RSAKeyProvider buildRsaKeyProvider(RSAPublicKey rsaPublicKey) {
        RSAKeyProvider rsaKeyProvider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return rsaPublicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                throw new NotImplementedException("Method is not implemented");
            }

            @Override
            public String getPrivateKeyId() {
                throw new NotImplementedException("Method is not implemented");
            }
        };
        return rsaKeyProvider;
    }

    /**
     * Gets the edts (external data to sign) hash from PoP token string
     * 
     * @param popToken The PoP token string
     * @return The edts (external data to sign) hash
     * @throws InvalidPopTokenException If edts (external data to sign) hash cannot be retrieved from PoP token
     */
    private String getEdts(DecodedJWT popToken) throws InvalidPopTokenException {
        Map<String, Claim> popTokenClaims = popToken.getClaims();
        if (!popTokenClaims.containsKey("edts")) {
            throw new InvalidPopTokenException("The edts is missing in PoP token payload");
        }
        return popTokenClaims.get("edts").asString();
    }

    /**
     * Validates the edts (external data to sign) hash by recalculating the hash using the specified ehtsKeyValueMap and then comparing
     * the recalculated hash with the existing hash value.
     * 
     * @param signedPopToken The signed PoP token
     * @param ehtsKeyValueMap The map containing the values for all the ehts (external headers to sign) keys
     * @throws PopTokenValidatorException If the edts (external data to sign) is invalid
     */
    private void validateEdtsHash(DecodedJWT signedPopToken, Map<String, String> ehtsKeyValueMap) throws PopTokenValidatorException {

        List<String> ehtsList = getEhts(signedPopToken);
        String actualEdtsHash = getEdts(signedPopToken);

        StringBuilder dataToHashBuilder = new StringBuilder();
        for (String ehtsKey : ehtsList) {
            if (!ehtsKeyValueMap.containsKey(ehtsKey)) {
                throw new PopTokenValidatorException("The ehtsKeyValueMap does not contain the entry for ehsKey '" + ehtsKey + "'");
            }
            dataToHashBuilder.append(ehtsKeyValueMap.get(ehtsKey));
        }
        String expectedEdtsHash = PopTokenValidatorUtils.sha256Base64UrlSafe(dataToHashBuilder.toString());
        boolean doesEdtsMatch = expectedEdtsHash.equalsIgnoreCase(actualEdtsHash);
        if (!doesEdtsMatch) {
            logger.debug("The edts doesn't match, actualEdtsHash: {}, expectedEdtsHash: {}", actualEdtsHash, expectedEdtsHash);
            throw new PopTokenInvalidEdtsHashException(
                    "The edts doesn't match, expectedEdtsHash: " + expectedEdtsHash + ", actualEdtsHash: " + actualEdtsHash);
        }
    }

    /**
     * Gets the list of ehts (external headers to sign) keys from signed PoP token.
     * 
     * @param popToken The signed PoP token.
     * @return The list of ehts (external headers to sign) keys
     * @throws InvalidPopTokenException If the ehts (external headers to sign) keys cannot be retrieved from PoP token
     */
    private List<String> getEhts(DecodedJWT popToken) throws InvalidPopTokenException {
        Map<String, Claim> popTokenClaims = popToken.getClaims();
        if (!popTokenClaims.containsKey("ehts")) {
            throw new InvalidPopTokenException("The ehts is missing in PoP token payload");
        }

        String ehts = popTokenClaims.get("ehts").asString();
        if (StringUtils.isBlank(ehts)) {
            throw new InvalidPopTokenException("The ehts is empty in PoP token payload");
        }
        return Arrays.asList(ehts.split(";"));
    }
}

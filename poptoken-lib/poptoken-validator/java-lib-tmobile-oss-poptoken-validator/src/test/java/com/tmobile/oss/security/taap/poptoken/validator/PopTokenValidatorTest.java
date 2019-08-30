package com.tmobile.oss.security.taap.poptoken.validator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tmobile.oss.security.taap.poptoken.validator.exception.InvalidPopTokenException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopPublicKeyParseException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenExpiredException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenInvalidEdtsHashException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenSignatureVerificationException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenValidatorException;
import com.tmobile.oss.security.taap.poptoken.validator.testhelper.PopTokenValidatorTestHelper;

public class PopTokenValidatorTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorTest.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void validatePopTokenWithPublicKeyPemString__validInput__validatesSuccessfully() throws Exception {

        // setup the data

        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        byte[] publicKeyBytes = rsaKeyPair.getPublic().getEncoded();
        String publicKeyPemString = PopTokenValidatorTestHelper.generatePublicKeyPemString(publicKeyBytes);

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyPemString(popToken, publicKeyPemString, ehtsKeyValueMap);
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("No exception should have been thrown");
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyPemString__nullPopTokenInput__throwsIllegalArgumentException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        byte[] publicKeyBytes = rsaKeyPair.getPublic().getEncoded();
        String publicKeyPemString = PopTokenValidatorTestHelper.generatePublicKeyPemString(publicKeyBytes);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyPemString(null, publicKeyPemString, new HashMap<>());
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals("The popToken should not be null or empty", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyPemString__invalidPopTokenInput__throwsInvalidPopTokenException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        byte[] publicKeyBytes = rsaKeyPair.getPublic().getEncoded();
        String publicKeyPemString = PopTokenValidatorTestHelper.generatePublicKeyPemString(publicKeyBytes);

        String popToken = "INVALID PoP Token";

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyPemString(popToken, publicKeyPemString, ehtsKeyValueMap);
            fail("The InvalidPopTokenException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(InvalidPopTokenException.class, ex.getClass());
            assertTrue("The actual error message: " + ex.getMessage(), ex.getMessage().startsWith("Couldn't decode the token"));
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyPemString__nullPublicKeyInput__throwsIllegalArgumentException() throws Exception {
        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyPemString("popToken", null, new HashMap<>());
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals("The publicKeyPemString should not be null or empty", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyPemString__nullEhtsKeyValueMap__throwsIllegalArgumentException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        byte[] publicKeyBytes = rsaKeyPair.getPublic().getEncoded();
        String publicKeyPemString = PopTokenValidatorTestHelper.generatePublicKeyPemString(publicKeyBytes);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyPemString("pop-token", publicKeyPemString, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyJwkString__validInput__validatesSuccessfully() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyJwkString = rsaPublicKeyToJwkString((RSAPublicKey) rsaKeyPair.getPublic(), UUID.randomUUID().toString());
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyJwkString(popToken, publicKeyJwkString, ehtsKeyValueMap);
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("No exception should have been thrown");
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyJwkString__nullPopTokenInput__throwsIllegalArgumentException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyJwkString = rsaPublicKeyToJwkString((RSAPublicKey) rsaKeyPair.getPublic(), UUID.randomUUID().toString());

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyJwkString(null, publicKeyJwkString, new HashMap<>());
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals("The popToken should not be null or empty", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyJwkString__invalidPopTokenInput__throwsInvalidPopTokenException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyJwkString = rsaPublicKeyToJwkString((RSAPublicKey) rsaKeyPair.getPublic(), UUID.randomUUID().toString());

        String popToken = "INVALID PoP Token";

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyJwkString(popToken, publicKeyJwkString, ehtsKeyValueMap);
            fail("The InvalidPopTokenException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(InvalidPopTokenException.class, ex.getClass());
            assertTrue("The actual error message: " + ex.getMessage(), ex.getMessage().startsWith("Couldn't decode the token"));
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyJwkString__nullPublicKeyInput__throwsIllegalArgumentException() throws Exception {
        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyJwkString("popToken", null, new HashMap<>());
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals("The publicKeyJwkString should not be null or empty", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyJwkString__invalidPublicKeyInput__throwsIllegalArgumentException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyJwkString = "INVALID JWK STRING";
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyJwkString(popToken, publicKeyJwkString, ehtsKeyValueMap);
            fail("The PopPublicKeyParseException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopPublicKeyParseException.class, ex.getClass());
            assertTrue("The actual error message: " + ex.getMessage(),
                    ex.getMessage().startsWith("Error occurred while converting jwkString to RSAPublicKey"));
        }
    }

    @Test
    public void validatePopTokenWithPublicKeyJwkString__nullEhtsKeyValueMap__throwsIllegalArgumentException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyJwkString = rsaPublicKeyToJwkString((RSAPublicKey) rsaKeyPair.getPublic(), UUID.randomUUID().toString());

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithPublicKeyJwkString("pop-token", publicKeyJwkString, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__validInput__validatesSuccessfully() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("No exception should have been thrown");
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__manipulatedPopToken__throwsPopTokenSignatureVerificationException()
            throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);
        String encodedPayloadOfPopToken = popToken.substring(popToken.indexOf(".") + 1, popToken.lastIndexOf("."));
        String decodedPayloadOfPopToken = new String(Base64.decodeBase64(encodedPayloadOfPopToken), Charsets.UTF_8);
        Map<String, Object> payloadOfPopTokenMap = objectMapper.readValue(decodedPayloadOfPopToken,
                new TypeReference<Map<String, Object>>() {
                });
        // modify the expiration time by adding 100 seconds
        payloadOfPopTokenMap.put("exp", ((Integer) payloadOfPopTokenMap.get("exp")) + 100);
        String modifiedPayloadOfPopToken = objectMapper.writeValueAsString(payloadOfPopTokenMap);
        String eoncodedModifiedPayloadOfPopToken = Base64.encodeBase64String(modifiedPayloadOfPopToken.getBytes());
        String manipulatedPopToken = popToken.substring(0, popToken.indexOf(".")) + "." + eoncodedModifiedPayloadOfPopToken + "."
                + popToken.substring(popToken.lastIndexOf(".") + 1);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(manipulatedPopToken, rsaPublicKey, ehtsKeyValueMap);
            fail("The PopTokenSignatureVerificationException should not have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenSignatureVerificationException.class, ex.getClass());
            assertTrue("The actual error message: " + ex.getMessage(), ex.getMessage().startsWith("Couldn't verify the signature"));
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__validInputMoreEhts__validatesSuccessfully() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put("Custom-Header-1", "Custom-Header-Value-1");
        ehtsKeyValueMap.put("Custom-Header-2", "Custom-Header-Value-2");
        ehtsKeyValueMap.put("Custom-Header-3", "Custom-Header-Value-3");
        ehtsKeyValueMap.put("Custom-Header-4", "Custom-Header-Value-4");
        ehtsKeyValueMap.put("Custom-Header-5", "Custom-Header-Value-5");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("No exception should have been thrown");
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__tokenIsInLeewayPeriod__validatesSuccessfully() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        /**
         * since our token is valid for 120 seconds (2 minutes) and leeway is 10 seconds, use issuedAt = currentTime - (2m and 8s),
         * this will ensure that token is in leeway period and still 2 seconds left before it expires
         */
        Date issuedAtDate = new Date(System.currentTimeMillis() - ((2 * 60 * 1000) + (8 * 1000)));
        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, issuedAtDate, 120, rsaPrivateKey);

        // validate the token is in leeway period
        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("No exception should have been thrown");
        }

        // now sleep for 2+ seconds end verify that the token is expired after that
        Thread.sleep(3001);

        // validate the token is now expired
        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
            fail("The PopTokenValidatorException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenExpiredException.class, ex.getClass());
            assertTrue("Actual error message: " + ex.getMessage(), ex.getMessage().startsWith("The token has expired"));
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__verifySignatureUsingNonMatchingPublicKey__ThrowsPopTokenSignatureVerificationException()
            throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);
        RSAPublicKey nonMatchingPublicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, nonMatchingPublicKey, ehtsKeyValueMap);
            fail("The PopTokenSignatureVerificationException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenSignatureVerificationException.class, ex.getClass());
            assertTrue("Actual error message: " + ex.getMessage(), ex.getMessage().startsWith("Couldn't verify the signature"));
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__expiredToken__throwsPopTokenValidatorException() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        // since our token is valid for 120 seconds (2 minutes) and leeway is 10 seconds, use issuedAt = currentTime - (2m and 11s)
        Date issuedAtDate = new Date(System.currentTimeMillis() - ((2 * 60 * 1000) + (11 * 1000)));
        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, issuedAtDate, 120, rsaPrivateKey);

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsKeyValueMap);
            fail("The PopTokenExpiredException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenExpiredException.class, ex.getClass());
            assertTrue("Actual error message: " + ex.getMessage(), ex.getMessage().startsWith("The token has expired"));
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__requestHeadersHaveBeenModified__throwsPopTokenValidatorException() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        // http request was manipulated so when it came to server the header values were different
        Map<String, String> ehtsKeyValueMapOfManipulatedRequest = new HashMap<>();
        ehtsKeyValueMapOfManipulatedRequest.put("Content-Type", "MODIFIED CONTENT TYPE");
        ehtsKeyValueMapOfManipulatedRequest.put("Authorization", "MODIFIED BEARER TOKEN");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey,
                    ehtsKeyValueMapOfManipulatedRequest);
            fail("The PopTokenValidatorException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenInvalidEdtsHashException.class, ex.getClass());
            assertTrue("Actual error message: " + ex.getMessage(), ex.getMessage().startsWith("The edts doesn't match"));
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__ehtsKeyValueMapDoesNotContainRequiredEhtsKeys__ThrowsPopTokenValidatorException()
            throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        Map<String, String> ehtsKeyValueMapToUseForPopTokenValidation = new HashMap<>();
        ehtsKeyValueMapToUseForPopTokenValidation.put("ehts-key-1", "ehts-value-1");
        ehtsKeyValueMapToUseForPopTokenValidation.put("ehts-key-2", "ehts-value-2");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey,
                    ehtsKeyValueMapToUseForPopTokenValidation);
            fail("The PopTokenValidatorException should have been thrown");
        } catch (PopTokenValidatorException ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenValidatorException.class, ex.getClass());
            assertEquals("The ehtsKeyValueMap does not contain the entry for ehsKey 'Content-Type'", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__nullPopTokenInput__throwsIllegalArgumentException() throws Exception {
        // setup the data
        RSAPublicKey publicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey(null, publicKey, new HashMap<>());
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals("The popToken should not be null or empty", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__nullPublicKeyInput__throwsIllegalArgumentException() throws Exception {
        // setup the data
        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey("popToken", null, new HashMap<>());
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals("The rsaPublicKey should not be null", ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__nullEhtsKeyValueMap__throwsIllegalArgumentException() throws Exception {
        // setup the data
        RSAPublicKey publicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey("pop-token", publicKey, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__ehtsKeyValueMapContainsNullEhtsKey__throwsIllegalArgumentException()
            throws Exception {
        // setup the data
        RSAPublicKey publicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put(null, "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey("pop-token", publicKey, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__ehtsKeyValueMapContainsEmptyEhtsKey__throwsIllegalArgumentException()
            throws Exception {
        // setup the data
        RSAPublicKey publicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("   ", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey("pop-token", publicKey, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__ehtsKeyValueMapContainsNullEhtsValue__throwsIllegalArgumentException()
            throws Exception {
        // setup the data
        RSAPublicKey publicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", null);
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey("pop-token", publicKey, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void validatePopTokenWithRsaPublicKey__ehtsKeyValueMapContainsEmptyEhtsValue__throwsIllegalArgumentException()
            throws Exception {
        // setup the data
        RSAPublicKey publicKey = (RSAPublicKey) PopTokenValidatorTestHelper.createRsaKeyPair().getPublic();
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "   ");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenValidator.newInstance().validatePopTokenWithRsaPublicKey("pop-token", publicKey, null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void getEhtsKeys__validInput__returnsEhtsKeysListSuccessfully() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<String, String>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        String popToken = PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);

        // perform an action
        List<String> actualEhtsKeys = PopTokenValidator.newInstance().getEhtsKeys(popToken);

        // validate the results
        assertEquals(new ArrayList<>(ehtsKeyValueMap.keySet()), actualEhtsKeys);
    }

    @Test
    public void getEhtsKeys__nullPopTokenInput__throwsIllegalArgumentException() throws Exception {

        try {
            // perform an action
            PopTokenValidator.newInstance().getEhtsKeys(null);
            fail("The IllegalArgumentException should have been thrown");
        } catch (Exception ex) {
            // validate the result
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(IllegalArgumentException.class, ex.getClass());
            assertTrue("Actual error message: " + ex.getMessage(),
                    ex.getMessage().startsWith("The popToken should not be null or empty"));
        }
    }

    @Test
    public void getEhtsKeys__invalidPopTokenInput__throwsInvalidPopTokenException() throws Exception {

        try {
            // perform an action
            PopTokenValidator.newInstance().getEhtsKeys("INVALID PoP TOKEN");
            fail("The test should have failed");
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(InvalidPopTokenException.class, ex.getClass());
            assertTrue("Actual error message: " + ex.getMessage(),
                    ex.getMessage().startsWith("Error occurred while parsing the PoP token"));
        }
    }

    // ===== helper methods ===== //
    private String rsaPublicKeyToJwkString(RSAPublicKey rsaPublicKey, String kid) throws JsonProcessingException {
        LinkedHashMap<String, String> jwkMap = new LinkedHashMap<>();
        jwkMap.put("alg", "RS256");
        jwkMap.put("e", Base64.encodeBase64URLSafeString(rsaPublicKey.getPublicExponent().toByteArray()));
        jwkMap.put("n", Base64.encodeBase64URLSafeString(rsaPublicKey.getModulus().toByteArray()));
        jwkMap.put("kid", kid);
        jwkMap.put("kty", "RSA");
        jwkMap.put("use", "sig");
        return objectMapper.writeValueAsString(jwkMap);
    }
}

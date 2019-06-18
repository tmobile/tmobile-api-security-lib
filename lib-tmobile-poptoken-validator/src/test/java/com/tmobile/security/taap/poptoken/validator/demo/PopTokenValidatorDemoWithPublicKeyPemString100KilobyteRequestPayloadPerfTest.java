package com.tmobile.security.taap.poptoken.validator.demo;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.security.taap.poptoken.builder.exception.PopTokenBuilderException;
import com.tmobile.security.taap.poptoken.validator.PopEhtsKey;
import com.tmobile.security.taap.poptoken.validator.PopTokenValidator;
import com.tmobile.security.taap.poptoken.validator.exception.PopTokenValidatorException;
import com.tmobile.security.taap.poptoken.validator.testhelper.PopTokenValidatorTestHelper;

public class PopTokenValidatorDemoWithPublicKeyPemString100KilobyteRequestPayloadPerfTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorDemoWithPublicKeyPemString100KilobyteRequestPayloadPerfTest.class);

    private static final int NUM_BYTES_IN_HUNDRED_KILOBYTE = 100 * 1024;
    private static final String HUNDRED_KILOBYTE_REQUEST_PAYLOAD = PopTokenValidatorTestHelper
            .createRequestPayload(NUM_BYTES_IN_HUNDRED_KILOBYTE);

    @Test
    public void validatePopTokenWithPublicKeyPemString() throws Exception {

        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyPemString = PopTokenValidatorTestHelper.generatePublicKeyPemString(rsaKeyPair.getPublic().getEncoded());
        String privateKeyPemString = PopTokenValidatorTestHelper.generatePrivateKeyPemString(rsaKeyPair.getPrivate().getEncoded());

        String popToken = buildPopTokenWithPrivateKeyPemString(privateKeyPemString);

        long startTime = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            doValidate(popToken, publicKeyPemString);
        }
        long processingTime = System.currentTimeMillis() - startTime;

        logger.info(
                "PopTokenValidatorDemoWithPublicKeyPemString100KilobytePerfTest -> actual processing time: " + processingTime + " ms"); //
        assertTrue("Should not have taken more than 6 seconds for 1000 validations, actual processing time: " + processingTime,
                (processingTime < 6000)); //
    }

    // ===== helper methods ===== //

    private void doValidate(String popToken, String publicKeyPemString) throws PopTokenValidatorException {
        // STEP 1: Create an instance of PoPTokenValidator
        PopTokenValidator popTokenValidator = PopTokenValidator.newInstance();

        // STEP 2: Get the list of ehts (external headers to sign) keys from the pop
        // token string
        List<String> ehtsKeys = popTokenValidator.getEhtsKeys(popToken);

        // STEP 3: Build map of ehts (external headers to sign) key-value pairs by
        // reading the required values from HTTP request
        Map<String, String> ehtsValuesMap = new HashMap<>();
        for (String ehtsKey : ehtsKeys) {
            ehtsValuesMap.put(ehtsKey, getEhtsValue(ehtsKey));
        }

        // STEP 4: Validate the PoP token using
        // PopTokenValidator.validatePopTokenWithPublicKeyPemString method, this method
        // will throw PopTokenValidatorException if the PoP token is invalid or the PoP token
        // cannot be validated
        popTokenValidator.validatePopTokenWithPublicKeyPemString(popToken, publicKeyPemString, ehtsValuesMap);
    }

    private String buildPopTokenWithPrivateKeyPemString(String privateKeyPemString) throws PopTokenBuilderException {
        // Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", getEhtsValue("Content-Type"));
        ehtsKeyValueMap.put("Authorization", getEhtsValue("Authorization"));
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), getEhtsValue(PopEhtsKey.URI.keyName()));
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), getEhtsValue(PopEhtsKey.HTTP_METHOD.keyName()));
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), getEhtsValue(PopEhtsKey.BODY.keyName()));

        // Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(privateKeyPemString) //
                .build();

        return popToken;

    }

    /**
     * This implementation is provided only for demonstrating the PoP token validation, in real use case these values should be read
     * from the HTTP request.
     * 
     * @param ehtsKey The ehts key
     * @return The value for the ehts key
     */
    private String getEhtsValue(String ehtsKey) {
        ehtsKey = ehtsKey.toLowerCase();
        if (ehtsKey.equals("content-type")) {
            return "application/json";
        } else if (ehtsKey.equals("authorization")) {
            return "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS";
        } else if (ehtsKey.equals("uri")) {
            return "/commerce/v1/orders";
        } else if (ehtsKey.equals("http-method")) {
            return "POST";
        } else if (ehtsKey.equals("body")) {
            return HUNDRED_KILOBYTE_REQUEST_PAYLOAD;
        } else {
            return null;
        }
    }
}
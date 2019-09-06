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

package com.tmobile.oss.security.taap.poptoken.validator.demo;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.oss.security.taap.poptoken.validator.PopEhtsKey;
import com.tmobile.oss.security.taap.poptoken.validator.PopTokenValidator;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenValidatorException;
import com.tmobile.oss.security.taap.poptoken.validator.testhelper.PopTokenValidatorTestHelper;

public class PopTokenValidatorDemoWith1MegabyteRequestPayloadPerfTest {

    private static final Logger logger = LoggerFactory
            .getLogger(PopTokenValidatorDemoWith1MegabyteRequestPayloadPerfTest.class);

    private static final int NUM_BYTES_IN_ONE_MEGABYTE = 1 * 1024 * 1024;
    private static final String HUNDRED_MEGABYTE_REQUEST_PAYLOAD = PopTokenValidatorTestHelper
            .createRequestPayload(NUM_BYTES_IN_ONE_MEGABYTE);

    @Test
    public void validatePopTokenWithPublicKeyPemString() throws Exception {

        KeyPair rsaKeyPair = PopTokenValidatorTestHelper.createRsaKeyPair();
        String publicKeyPemString = PopTokenValidatorTestHelper.generatePublicKeyPemString(rsaKeyPair.getPublic().getEncoded());

        String popToken = buildPopTokenWithRsaPrivateKey((RSAPrivateKey) rsaKeyPair.getPrivate());

        long startTime = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            doValidate(popToken, publicKeyPemString);
        }

        long actualProcessingTime = System.currentTimeMillis() - startTime;
        long expectedProcessingTime = 30000L;

        logger.info("validatePopTokenWithPublicKeyPemString -> actualProcessingTime: " + actualProcessingTime + " ms"); //
        assertTrue("Should not have taken more than " + expectedProcessingTime + " millis for 1000 validations, actualProcessingTime: "
                + actualProcessingTime, (actualProcessingTime <= expectedProcessingTime)); //
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

    private String buildPopTokenWithRsaPrivateKey(RSAPrivateKey rsaPrivateKey) {
        // Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", getEhtsValue("Content-Type"));
        ehtsKeyValueMap.put("Authorization", getEhtsValue("Authorization"));
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), getEhtsValue(PopEhtsKey.URI.keyName()));
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), getEhtsValue(PopEhtsKey.HTTP_METHOD.keyName()));
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), getEhtsValue(PopEhtsKey.BODY.keyName()));

        // create a PoP token
        return PopTokenValidatorTestHelper.createPopToken(ehtsKeyValueMap, new Date(), 120, rsaPrivateKey);
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
            return HUNDRED_MEGABYTE_REQUEST_PAYLOAD;
        } else {
            return null;
        }
    }
}
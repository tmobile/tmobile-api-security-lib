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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.oss.security.taap.poptoken.validator.PopEhtsKey;
import com.tmobile.oss.security.taap.poptoken.validator.PopTokenValidator;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenExpiredException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenValidatorException;

public class PopTokenValidatorDemoWithPublicKeyJwkStringTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorDemoWithPublicKeyJwkStringTest.class);
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void validatePopTokenWithRsaPublicKey() throws Exception {

        String popToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJlZHRzIjoiYWZxR1dBYlNldlRQMm0zOHF1QmpDOHBBMkhjeFpYRzR6cEZDUFNoVHRTbyIsInYiOiIxIiwiZXhwIjoxNTY3MjAzMjAxLCJlaHRzIjoiQ29udGVudC1UeXBlO0F1dGhvcml6YXRpb247dXJpO2h0dHAtbWV0aG9kO2JvZHkiLCJpYXQiOjE1NjcyMDMwODEsImp0aSI6IjgzZWNiY2QyLTU4ODMtNDRjNy05NDcwLTcxZTAyZTViZTBkYyJ9.IPVCvaUbTs98MpYG2JfDNnziYa1nhJfihcabL-jgLPIGkf1T0IqqHdpihLnRl65Fj_Y3elJrbVCP5odRtVmr8EKmsNVlQykVFfTuXvswv_d3xnlNVghEkYlMnomoa_e_FiKSgUAdz-42iZsBl3Vjql4V1igk2MdiKaGGmKDavi-pe_kU8jPdHIWlogE6SkHVtTJ31dDdzh3ijAPqizIyueZ2J10EvEojPnMzPryKrkybrVAQyb1hSvqCmxQth_1L0IyXKkXrpqdY7SoX03yRDFH2kBODZcHAIxNxQn6XAWC9z_RS8y6cGeTUlGH_jXKPqCpdfKD5UIeFdrPkcawiCw";

        String publicKeyJwkString = "{" + LINE_SEPARATOR //
                + "  \"alg\": \"RS256\"," + LINE_SEPARATOR //
                + "  \"e\": \"AQAB\"," + LINE_SEPARATOR //
                + "  \"n\": \"maGCOzVBAqcAD6JhOb5YYdhiKWlvVotTOzCsu6VxK2Uzb2tKhVYGd5hpgB_MFkbH64YPqIAn-IN7IUwvbkP4pDLF0kZ6uGAo1zFfmbACFlgBgB8HciMS1_zBCBnhtpPSm8K-6Ik66i20g6VfZ9HVyXxB8fcEO1fLgxz6Je_TF-TTXWtLMWaGE6zLFT0SJox5O3EsrstzwFDh1MNjba9Thn4PoOkn4rrT8nSdPRTRxphaLBR-ch3gVvykOSLJqVrmcQxJwAiCcNlIMXFgjpVpnY4n9Nz9wDHznr_a-qOI2w8nSGIHIdhT8wRj4Cf72DS1huIwIrMw1LQzM_hl7ZuGQw==\","
                + LINE_SEPARATOR //
                + "  \"kid\": \"dfad17ce-073b-4421-9944-fc9477c2bd63\"," + LINE_SEPARATOR //
                + "  \"kty\": \"RSA\"," + LINE_SEPARATOR //
                + "  \"use\": \"sig\"" + LINE_SEPARATOR //
                + "}"; // LINE_SEPARATOR //

        try {
            // STEP 1: Create an instance of PoPTokenValidator
            PopTokenValidator popTokenValidator = PopTokenValidator.newInstance();

            // STEP 2: Get the list of ehts (external headers to sign) keys from the pop token string
            List<String> ehtsKeys = popTokenValidator.getEhtsKeys(popToken);

            // STEP 3: Build map of ehts (external headers to sign) key-value pairs by reading the required values from HTTP request
            Map<String, String> ehtsValuesMap = new HashMap<>();
            for (String ehtsKey : ehtsKeys) {
                ehtsValuesMap.put(ehtsKey, getEhtsValue(ehtsKey));
            }

            // STEP 4: Validate the PoP token using PopTokenValidator.validatePopToken method, this method will throw
            // PopTokenValidatorException if the PoP token is invalid or the PoP token cannot be validated
            popTokenValidator.validatePopTokenWithPublicKeyJwkString(popToken, publicKeyJwkString, ehtsValuesMap);
            fail("The PopTokenValidatorException should have been thrown as the this is an expired token");
        } catch (PopTokenValidatorException ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenExpiredException.class, ex.getClass());
        }
    }

    // ===== helper methods ===== //

    /**
     * This implementation is provided only for demonstrating the PoP token validation, in real use case these values should be read
     * from the HTTP request.
     * 
     * @param ehtsKey The ehts key
     * @return The value for the ehts key
     */
    private String getEhtsValue(String ehtsKey) {
        if (ehtsKey.equals("Content-Type")) {
            return "application/json";
        } else if (ehtsKey.equals("Authorization")) {
            return "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS";
        } else if (ehtsKey.equals(PopEhtsKey.HTTP_METHOD.keyName())) {
            return "POST";
        } else if (ehtsKey.equals(PopEhtsKey.URI.keyName())) {
            return "/commerce/v1/orders";
        } else if (ehtsKey.equals(PopEhtsKey.BODY.keyName())) {
            return "{\"orderId\": 100, \"product\": \"Mobile Phone\"}";
        } else {
            return null;
        }
    }
}
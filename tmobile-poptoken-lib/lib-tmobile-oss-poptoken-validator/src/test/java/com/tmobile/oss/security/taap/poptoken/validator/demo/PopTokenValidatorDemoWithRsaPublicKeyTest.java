package com.tmobile.oss.security.taap.poptoken.validator.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.security.interfaces.RSAPublicKey;
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
import com.tmobile.oss.security.taap.poptoken.validator.utils.PopTokenValidatorUtils;

public class PopTokenValidatorDemoWithRsaPublicKeyTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorDemoWithRsaPublicKeyTest.class);
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void validatePopTokenWithRsaPublicKey() {

        String popToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJlZHRzIjoiRmtHalFWWWNuZ0VkZ3lPa3BiQjFUVWI2X19jenFib25wUVZDc2Y1Y3J3RSIsInYiOiJ2MSIsImV4cCI6MTU2MTA3MjIyNywiZWh0cyI6IkNvbnRlbnQtVHlwZTtBdXRob3JpemF0aW9uO3VyaTtodHRwLW1ldGhvZDtib2R5IiwiaWF0IjoxNTYxMDcyMTA3LCJqdGkiOiI2ZDlmOGQ3Zi01ZTM3LTRiNWItYTJiMC00M2E0YzllY2Q2ODkifQ.k7DYvg7kGYE8OosqkvGBAkktATbRcr1YdqefX5N0bc_yWTLd_1TXseZ6e2dr7E9UkDwN4FfZ8hbm8IF7oQy3BOgws5kt_u_x-HluGlESQLIsX1BoNGGrCyDX7gBgeDc-P0z70UJXi5r_VJz8WLoEyp3ZS14I3HlSJAuYwdTvf207j3Chj5iCA9B6TfRORbc-3ua35K_3OL8WckXfUGpkLDitDvA_BXxN4_pMCrTXBEYCxhWl4ZJcIuL3T8uGPFkug_Vcz_Wojdv4BauY-M_elfcXpM6-D_L8dE5hWrSAXZPnRN36rb0QhYeXO80zFtY3SuM0-CoC6_EoaVhZ28VCAA";

        String publicKeyPemString = "-----BEGIN PUBLIC KEY-----" + LINE_SEPARATOR //
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr6yrypbkrAT+4m0yU5sz" + LINE_SEPARATOR //
                + "udm0Cm0NM5AOxU1x7Nx9hYRYrxbh+LFamxBGAKhO3Ej2ORfWyXtw1BuVXxheHGC9" + LINE_SEPARATOR //
                + "CnNCozCh3OX15Rf23z+JeI2jGfa+JxiQ4qRBl53hMDOMEWp745aOr/bKOwnM6FCT" + LINE_SEPARATOR //
                + "DlcKb/8N0ydJiiuX3gk2JX5pmZtiKgHsIaX/4O65fF42r4pRKw23RouCyqjTTWqt" + LINE_SEPARATOR //
                + "OYrZSHFKwTp7VhCYXmjf87B6GO23YIF/TVJfkZ+b1LBKg+RTUqFeJgEvjEZka0Ug" + LINE_SEPARATOR //
                + "r/t/tRzZsTLRMG38ENd0KDbsqtmILcLL7bCglyzdPS1HmOQIQwO7zKN8tZjNrGvO" + LINE_SEPARATOR //
                + "SwIDAQAB" + LINE_SEPARATOR //
                + "-----END PUBLIC KEY-----" + LINE_SEPARATOR; //

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

            // STEP 4: Create RSAPublicKey from publicKeyPemString
            RSAPublicKey rsaPublicKey = PopTokenValidatorUtils.keyPemStringToRsaPublicKey(publicKeyPemString);

            // STEP 5: Validate the PoP token using PopTokenValidator.validatePopToken method, this method will throw
            // PopTokenValidatorException if the PoP token is invalid or the PoP token cannot be validated
            popTokenValidator.validatePopTokenWithRsaPublicKey(popToken, rsaPublicKey, ehtsValuesMap);
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
            return "post";
        } else if (ehtsKey.equals(PopEhtsKey.URI.keyName())) {
            return "/commerce/v1/orders";
        } else if (ehtsKey.equals(PopEhtsKey.BODY.keyName())) {
            return "{\"orderId\": 100, \"product\": \"Mobile Phone\"}";
        } else {
            return null;
        }
    }
}
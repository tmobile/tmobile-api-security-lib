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

import com.tmobile.oss.security.taap.poptoken.validator.PopTokenValidator;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenExpiredException;
import com.tmobile.oss.security.taap.poptoken.validator.exception.PopTokenValidatorException;
import com.tmobile.oss.security.taap.poptoken.validator.utils.PopTokenValidatorUtils;

public class PopTokenValidatorDemoWithRsaPublicKeyTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorDemoWithRsaPublicKeyTest.class);
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void validatePopTokenWithRsaPublicKey() {

        String popToken = "eyJhbGciOiJSUzI1NiJ9.eyJlZHRzIjoiSFU0VVk2cTUxOElQNmt2YkpITURzUm11SllialdpZEtMWHpRS1c5R3hXRT0iLCJ2IjoidjEiLCJleHAiOjE1Mzc0MDQzNTMsImVodHMiOiJDb250ZW50LVR5cGU7QXV0aG9yaXphdGlvbiIsImlhdCI6MTUzNzQwNDIzMywianRpIjoiNjdlMTA4ZGEtOTBjZi00YzNiLWIwMjMtNTA4Mjc2Yjc0OTA2In0.csI2uOC8nKWNbnLxj8nwD5KTUHgjf7BKuRqtcUXX5EdejOLKqjci7295WYWZUMDSgQV3jqNgbPFRyc7e5cwOuT098CNCFYx6tFYWFRcZViGSeEkSbsxTe9_H1iwQjt2GI7iotaGTw02FXTZ06nVeljd3076CNGE9lFFjJ9y8FdpiGbUtdG3kCRAJ1KPLya9xHrTSXqpI0TBpa3chJ7D1PdDadAPOlMqP_C-UqkrrQzUi5GT2lcc-q_-EVaQGIulmkY1dy5ns57BMyFyvFiSKdyZRhTuBZgcJEROZM_eG-DY6S5TOlSxDP16SWF0liN2L1h5CWAsmSssMAZODhz6_LA";

        String publicKeyPemString = "-----BEGIN RSA PUBLIC KEY-----" + LINE_SEPARATOR //
                + "MIIBCgKCAQEAiQAMi3pPpY0fPAu7pJZfdp/HunsMtFgS7R7pHAmHJO6ejC7aVcSK" + LINE_SEPARATOR //
                + "8DM4yEAjQC1IbwkIKPINbXC+OiJSVzFko6YZNnVeOZKwtpOnFFZMUGpzX6H15Ty7" + LINE_SEPARATOR //
                + "bph+f4a/za2Awgl0X5sZTO2WvEeoHMr1ziUx0bwvts5MVxFpa6M062eTbQv9c45K" + LINE_SEPARATOR //
                + "Hr0Lm/UBC2r9TccR2lhrboDFe608OUe9a7YQe6G2yz8rXjugF1/qHaLYnvEln+Dk" + LINE_SEPARATOR //
                + "Haq/mH70AHFndnmfbjDV/lTpxa5eGZh37syDMdEbzpFkPHs80XPeJx4GjZW/In0w" + LINE_SEPARATOR //
                + "D37+9+mBVLA2JHZFyeRAB+hpHMIvlLbRSwIDAQAB" + LINE_SEPARATOR //
                + "-----END RSA PUBLIC KEY-----" + LINE_SEPARATOR; //

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
        } else {
            return null;
        }
    }
}
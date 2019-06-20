## T-Mobile PoP Token Validator
  
---
  
### Build/Install PoP Token Builder Library

Execute following command to build the PoP token builder library.

```
mavenGoals: clean install
```

<br>

---

### Implementation Details  
The T-Mobile PoP Validator library performs the following validations:

* Validates the exp (expiration time) claim to ensure the token is still valid (uses 10 seconds of leeway time).
* Validates the signature using the specified public key.
* Validates the edts (external data to sign) / ehts (external headers to sign) by recalculating the SHA256 hash and comparing it with the actual edts claim value.

**Notes:**

* If the API request body is very large or data is being streamed then the "body" should not be added to ehts/edts while building/validating the PoP token.

---

### Determining the ehts Key Name

* For HTTP request URI, "uri" should be used as ehts key name, `PopEhtsKey.URI.keyName()`. For "uri" ehts value, the URI and query string of the request URL should be put in the ehts key-value map. Example: If the URL is `https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000` then only `/commerce/v1/orders?account-number=0000000000` should be used as ehts value. The query parameter values part of "uri" ehts value should be in URL encoded format. 
* For HTTP method, "http-method" should be used as ehts key name, `PopEhtsKey.HTTP_METHOD.keyName()`.  
* For HTTP request headers, the header name should be used as ehts key name.  
* For HTTP request body, "body" should be used as ehts key name, `PopEhtsKey.BODY.keyName()`.  

---
  
### PoP Token Validator Performance Test Results
The following table shows the processing time taken by PoP token validation for various test cases.
  
| Test Name                           | Total Processing Time For 1000 Calls | Avg Processing Time For 1 Call |
|-------------------------------------|--------------------------------------|--------------------------------|
| PoP token with no request payload   | 549 ms                               | ~1 ms                          |
| PoP token with 1K request payload   | 540 ms                               | ~1 ms                          |
| PoP token with 10K request payload  | 777 ms                               | ~1 ms                          |
| PoP token with 100K request payload | 1999 ms                              | ~2 ms                          |
| PoP token with 1M request payload   | 16111 ms                             | ~16 ms                         |
  
---
    
### Validating the PoP Token Using Public Key PEM String
The following Java JUnit test describes how to validate the PoP token with the public key PEM string.

```
package com.tmobile.security.taap.poptoken.validator.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.security.taap.poptoken.validator.PopTokenValidator;
import com.tmobile.security.taap.poptoken.validator.exception.PopTokenExpiredException;
import com.tmobile.security.taap.poptoken.validator.exception.PopTokenValidatorException;

public class PopTokenValidatorDemoWithPublicKeyPemStringTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorDemoWithPublicKeyPemStringTest.class);
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void validatePopTokenWithPublicKeyPemString() {

        String popToken = "eyJhbGciOiJSUzI1NiJ9.eyJlZHRzIjoiSFU0VVk2cTUxOElQNmt2YkpITURzUm11SllialdpZEtMWHpRS1c5R3hXRT0iLCJ2IjoidjEiLCJleHAiOjE1Mzc0MDQzNTMsImVodHMiOiJDb250ZW50LVR5cGU7QXV0aG9yaXphdGlvbiIsImlhdCI6MTUzNzQwNDIzMywianRpIjoiNjdlMTA4ZGEtOTBjZi00YzNiLWIwMjMtNTA4Mjc2Yjc0OTA2In0.csI2uOC8nKWNbnLxj8nwD5KTUHgjf7BKuRqtcUXX5EdejOLKqjci7295WYWZUMDSgQV3jqNgbPFRyc7e5cwOuT098CNCFYx6tFYWFRcZViGSeEkSbsxTe9_H1iwQjt2GI7iotaGTw02FXTZ06nVeljd3076CNGE9lFFjJ9y8FdpiGbUtdG3kCRAJ1KPLya9xHrTSXqpI0TBpa3chJ7D1PdDadAPOlMqP_C-UqkrrQzUi5GT2lcc-q_-EVaQGIulmkY1dy5ns57BMyFyvFiSKdyZRhTuBZgcJEROZM_eG-DY6S5TOlSxDP16SWF0liN2L1h5CWAsmSssMAZODhz6_LA";

        String publicKeyPemString = "-----BEGIN PUBLIC KEY-----" + LINE_SEPARATOR //
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiQAMi3pPpY0fPAu7pJZf" + LINE_SEPARATOR //
                + "dp/HunsMtFgS7R7pHAmHJO6ejC7aVcSK8DM4yEAjQC1IbwkIKPINbXC+OiJSVzFk" + LINE_SEPARATOR //
                + "o6YZNnVeOZKwtpOnFFZMUGpzX6H15Ty7bph+f4a/za2Awgl0X5sZTO2WvEeoHMr1" + LINE_SEPARATOR //
                + "ziUx0bwvts5MVxFpa6M062eTbQv9c45KHr0Lm/UBC2r9TccR2lhrboDFe608OUe9" + LINE_SEPARATOR //
                + "a7YQe6G2yz8rXjugF1/qHaLYnvEln+DkHaq/mH70AHFndnmfbjDV/lTpxa5eGZh3" + LINE_SEPARATOR //
                + "7syDMdEbzpFkPHs80XPeJx4GjZW/In0wD37+9+mBVLA2JHZFyeRAB+hpHMIvlLbR" + LINE_SEPARATOR //
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

            // STEP 4: Validate the PoP token using PopTokenValidator.validatePopTokenWithPublicKeyPemString method, this method will
            // throw PopTokenValidatorException if the PoP token is invalid or the PoP token cannot be validated
            popTokenValidator.validatePopTokenWithPublicKeyPemString(popToken, publicKeyPemString, ehtsValuesMap);
            fail("The JwtTokenValidatorException should have been thrown as the this is an expired token");
        } catch (PopTokenValidatorException ex) {
            logger.error("Error occurred while validating the PoP token, error: " + ex.getMessage(), ex);
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
```
### Javadoc for validatePopTokenWithPublicKeyPemString Method

#### `public void validatePopTokenWithPublicKeyPemString(String popToken, String publicKeyPemString, Map<String, String> ehtsKeyValueMap) throws PopTokenValidatorException`

Validates the PoP token with public key PEM string.

 * **Parameters:**
   * `popToken` — The PoP token string
   * `publicKeyPemString` — The public key PEM string to verify the PoP token signature
   * `ehtsKeyValueMap` — The map containing the values for all the ehts (external headers to sign) keys.
     <p>
     Determining the ehts key name:
     <ul>
     <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     of "uri" ehts should be in URL encoded format.</li>
     <li>For HTTP method, "http-method" should be used as ehts key name, <code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     </ul>
     <p>
 * **Exceptions:**
   * `IllegalArgumentException` — If the popToken is null or empty, <br>
     publicKeyPemString is null or empty or ehtsKeyValueMap is invalid
   * `InvalidPopTokenException` — If the PoP token is invalid and so cannot be decoded
   * `PopTokenExpiredException` — If the PoP token is expired
   * `PopTokenSignatureVerificationException` — If the PoP token signature resulted invalid
   * `PopTokenInvalidEdtsHashException` — If the edts (external data to sign) hash is invalid
   * `PopTokenValidatorException` — If the PoP token cannot be validated
  
---
  
### Validating the PoP Token Using RSAPublicKey  
The following Java JUnit test describes how to validate the PoP token with the RSAPublicKey.  
  
```
package com.tmobile.security.taap.poptoken.validator.demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.security.taap.poptoken.validator.PopTokenValidator;
import com.tmobile.security.taap.poptoken.validator.exception.PopTokenExpiredException;
import com.tmobile.security.taap.poptoken.validator.exception.PopTokenValidatorException;
import com.tmobile.security.taap.poptoken.validator.utils.PopTokenValidatorUtils;

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
            fail("The JwtTokenValidatorException should have been thrown as the this is an expired token");
        } catch (PopTokenValidatorException ex) {
            logger.error("Error occurred while validating the PoP token, error: " + ex.getMessage(), ex);
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
```
### Javadoc for validatePopTokenWithRsaPublicKey Method

#### `public void validatePopTokenWithRsaPublicKey(String popToken, RSAPublicKey rsaPublicKey, Map<String, String> ehtsKeyValueMap) throws PopTokenValidatorException`

Validates the PoP token with RSA public key.

 * **Parameters:**
   * `popToken` — The PoP token string
   * `rsaPublicKey` — The RSAPublicKey to verify the PoP token signature
   * `ehtsKeyValueMap` — The map containing the values for all the ehts (external headers to sign) keys.
     <p>
     Determining the ehts key name:
     <ul>
     <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     of "uri" ehts should be in URL encoded format.</li>
     <li>For HTTP method, "http-method" should be used as ehts key name, <code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     </ul>
     <p>
 * **Exceptions:**
   * `IllegalArgumentException` — If the popToken is null or empty, rsaPublicKey is null or ehtsKeyValueMap is invalid
   * `InvalidPopTokenException` — If the PoP token is invalid and so cannot be decoded
   * `PopTokenExpiredException` — If the PoP token is expired
   * `PopTokenSignatureVerificationException` — If the PoP token signature resulted invalid
   * `PopTokenInvalidEdtsHashException` — If the edts (external data to sign) hash is invalid
   * `PopTokenValidatorException` — If the PoP token cannot be validated
  
---

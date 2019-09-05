# Java - PoP Token Validator Library

  
## Build/Install PoP Token Validator Library

Execute following command to build the PoP token validator library.

```bash
mvn clean install
```

  
## Implementation Details  
The T-Mobile PoP Validator library performs the following validations:

* Validates the exp (expiration time) claim to ensure the token is still valid (uses 10 seconds of leeway time).
* Validates the signature using the specified public key.
* Validates the edts (external data to sign) / ehts (external headers to sign) by recalculating the SHA256 hash and comparing it with the actual edts claim value.
* Current PoP token builder and validator libraries support RSA PKCS8 format key for signing and validating the PoP tokens.


**Notes:**

* If the API request body is very large or data is being streamed then the "body" should not be added to ehts/edts while building/validating the PoP token.

  
## Determining the ehts Key Name

* For HTTP request URI, "uri" should be used as ehts key name, `PopEhtsKey.URI.keyName()`. For "uri" ehts value, the URI and query string of the request URL should be put in the ehts key-value map. Example: If the URL is `https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000` then only `/commerce/v1/orders?account-number=0000000000` should be used as ehts value. The query parameter values part of "uri" ehts value should not be in URL encoded format. 
* For HTTP method, "http-method" should be used as ehts key name, `PopEhtsKey.HTTP_METHOD.keyName()`.  
* For HTTP request headers, the header name should be used as ehts key name.  
* For HTTP request body, "body" should be used as ehts key name, `PopEhtsKey.BODY.keyName()`.  


## Supported Key Format

PoP token builder and validator libraries are currently supporting PKCS8 key format.

**Using Non Encrypted Keys:**

Below commands shows how to create private and public keys in PKCS8 format:

```bash
# Creates private key in PKCS1 format
openssl genrsa -out private-key-pkcs1.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private-key-pkcs1.pem -outform PEM -nocrypt -out private-key-pkcs8.pem

# Creates public key in PKCS8 format
openssl rsa -in private-key-pkcs8.pem -outform PEM -pubout -out public-key.pem

```

**Using AES256 Encrypted Keys:**

Below commands shows how to create AES256 encrypted private key and public key in PCS8 format:

```bash
# Creates encrypted private key in PKCS1 format
openssl genrsa -aes256 -passout pass:foobar -out private_key_aes256_with_password.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private_key_aes256_with_password.pem -outform PEM -out private_key_aes256_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar

# Creates public key
openssl rsa -in private_key_aes256_with_password_pkcs8.pem -passin pass:foobar -outform PEM -pubout -out public-key.pem

```

**Using DES3 Encrypted Keys:**

Below commands shows how to create DES3 encrypted private key and public key in PKCS8 format:

```bash
# Creates encrypted private key in PKCS1 format
openssl genrsa -des3 -passout pass:foobar -out private_key_des3_with_password.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private_key_des3_with_password.pem -outform PEM -out private_key_des3_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar

# Creates public key
openssl rsa -in private_key_des3_with_password_pkcs8.pem -passin pass:foobar -outform PEM -pubout -out public-key.pem

```

  
## PoP Token Validator Performance Test Results
The following table shows the processing time taken by PoP token validation for various test cases.
  
| Test Name                           | Total Processing Time For 1000 Calls | Avg Processing Time For 1 Call |
|-------------------------------------|--------------------------------------|--------------------------------|
| PoP token with no request payload   | 549 ms                               | ~1 ms                          |
| PoP token with 1K request payload   | 540 ms                               | ~1 ms                          |
| PoP token with 10K request payload  | 777 ms                               | ~1 ms                          |
| PoP token with 100K request payload | 1999 ms                              | ~2 ms                          |
| PoP token with 1M request payload   | 16111 ms                             | ~16 ms                         |

  
## Validating the PoP Token Using Public Key PEM String
The following Java JUnit test describes how to validate the PoP token with the public key PEM string.

```java
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

public class PopTokenValidatorDemoWithPublicKeyPemStringTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorDemoWithPublicKeyPemStringTest.class);
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void validatePopTokenWithPublicKeyPemString() {

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

            // STEP 4: Validate the PoP token using PopTokenValidator.validatePopTokenWithPublicKeyPemString method, this method will
            // throw PopTokenValidatorException if the PoP token is invalid or the PoP token cannot be validated
            popTokenValidator.validatePopTokenWithPublicKeyPemString(popToken, publicKeyPemString, ehtsValuesMap);
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
```
  
## Javadoc for validatePopTokenWithPublicKeyPemString Method

**public void validatePopTokenWithPublicKeyPemString(String popToken, String publicKeyPemString, Map<String, String> ehtsKeyValueMap) throws PopTokenValidatorException**

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
     of "uri" ehts should not be in URL encoded format.</li>
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
 
 
## Validating the PoP Token Using Public Key JWK String
The following Java JUnit test describes how to validate the PoP token with public key JWK string.

```java
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

            // STEP 4: Validate the PoP token using PopTokenValidator.validatePopTokenWithPublicKeyJwkString method, this method will throw
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
```
  
## Javadoc for validatePopTokenWithPublicKeyJwkString Method

**public void validatePopTokenWithPublicKeyJwkString(String popToken, String publicKeyJwkString, Map<String, String> ehtsKeyValueMap) throws PopTokenValidatorException**

Validates the PoP token with public key JWK string.

 * **Parameters:**
   * `popToken` — The PoP token string
   * `publicKeyJwktring` — The public key JWK string to verify the PoP token signature
   * `ehtsKeyValueMap` — The map containing the values for all the ehts (external headers to sign) keys.
     <p>
     Determining the ehts key name:
     <ul>
     <li>For HTTP request URI, "uri" should be used as ehts key name, <code>PopEhtsKey.URI.keyName()</code>. <br>
     For "uri" ehts value, URI and query string of the request URL should be put in the map. Example: If the URL is
     "https://api.t-mobile.com/commerce/v1/orders?account-number=0000000000" then only
     "/commerce/v1/orders?account-number=0000000000" should be used as ehts "uri" value. The query parameter values part
     of "uri" ehts should not be in URL encoded format.</li>
     <li>For HTTP method, "http-method" should be used as ehts key name, <code>PopEhtsKey.HTTP_METHOD.keyName()</code>.</li>
     <li>For HTTP request headers, the header name should be used as ehts key name.</li>
     <li>For HTTP request body, "body" should be used as ehts key name, <code>PopEhtsKey.BODY.keyName()</code>.</li>
     </ul>
     <p>
 * **Exceptions:**
   * `IllegalArgumentException` — If the popToken is null or empty, <br>
     publicKeyJwkString is null or empty or ehtsKeyValueMap is invalid
   * `InvalidPopTokenException` — If the PoP token is invalid and so cannot be decoded
   * `PopTokenExpiredException` — If the PoP token is expired
   * `PopTokenSignatureVerificationException` — If the PoP token signature resulted invalid
   * `PopTokenInvalidEdtsHashException` — If the edts (external data to sign) hash is invalid
   * `PopTokenValidatorException` — If the PoP token cannot be validated
   
   
## Validating the PoP Token Using RSAPublicKey
The following Java JUnit test describes how to validate the PoP token with the RSAPublicKey.
  
```java
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

            // STEP 5: Validate the PoP token using PopTokenValidator.validatePopTokenWithRsaPublicKey method, this method will throw
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
```
  
## Javadoc for validatePopTokenWithRsaPublicKey Method

**public void validatePopTokenWithRsaPublicKey(String popToken, RSAPublicKey rsaPublicKey, Map<String, String> ehtsKeyValueMap) throws PopTokenValidatorException**

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
     of "uri" ehts should not be in URL encoded format.</li>
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

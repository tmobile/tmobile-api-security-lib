# Java - PoP Token Builder Library
  

## Build/Install PoP Token Builder Library

Execute following command to build the PoP token builder library.

```
mvn clean install
```


## Implementation Details  
The T-Mobile PoP Token Builder library follows the following logic for creating the PoP token.

* Sets up the edts (external data to sign) / ehts (external headers to sign) claims in PoP token using the specified ehts key-value map. The library uses SHA256 algorithm for calculating the edts and then the final edts value is encoded using Base64 URL encoding.
* Signs the PoP token using the specified RSA private key.
* Creates the PoP token with 2 minutes of validity period.
* Current PoP token builder and validator libraries support RSA PKCS8 format key for signing and validating the PoP tokens.


**Notes:**

* PopTokenBuilder is not thread-safe so the instance of this class should not be shared with between multiple threads.
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

```
# Creates private key in PKCS1 format
openssl genrsa -out private-key-pkcs1.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private-key-pkcs1.pem -outform PEM -nocrypt -out private-key-pkcs8.pem

# Creates public key in PKCS8 format
openssl rsa -in private-key-pkcs8.pem -outform PEM -pubout -out public-key.pem

```

**Using AES256 Encrypted Keys:**

Below commands shows how to create AES256 encrypted private key and public key in PCS8 format:

```
# Creates encrypted private key in PKCS1 format
openssl genrsa -aes256 -passout pass:foobar -out private_key_aes256_with_password.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private_key_aes256_with_password.pem -outform PEM -out private_key_aes256_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar

# Creates public key
openssl rsa -in private_key_aes256_with_password_pkcs8.pem -passin pass:foobar -outform PEM -pubout -out public-key.pem

```

**Using DES3 Encrypted Keys:**

Below commands shows how to create DES3 encrypted private key and public key in PKCS8 format:

```
# Creates encrypted private key in PKCS1 format
openssl genrsa -des3 -passout pass:foobar -out private_key_des3_with_password.pem 2048

# Converts private key to PKCS8 format
openssl pkcs8 -topk8 -inform PEM -in private_key_des3_with_password.pem -outform PEM -out private_key_des3_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar

# Creates public key
openssl rsa -in private_key_des3_with_password_pkcs8.pem -passin pass:foobar -outform PEM -pubout -out public-key.pem

```

**Minimum Java Requirement for Encrypted Private Keys:**

In order to use **AES256** or **DES3** encrypted private keys, it is required to either use Java version >= 8u161 OR have the Java Cryptographic Extension (JCE) Unlimited Strength Jurisdiction Policy Files installed. Please checkout following links for more information.

https://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8170157
https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

  
## PoP Token Builder Performance Test Results
The following table shows the processing time taken by PoP token builder for various test cases.
  
| Test Name                           | Total Processing Time For 1000 Calls | Avg Processing Time For 1 Call |
|-------------------------------------|--------------------------------------|--------------------------------|
| PoP token with no request payload   | 11383 ms                             | ~11 ms                         |
| PoP token with 1K request payload   | 10558 ms                             | ~11 ms                         |
| PoP token with 10K request payload  | 11484 ms                             | ~11 ms                         |
| PoP token with 100K request payload | 11239 ms                             | ~11 ms                         |
| PoP token with 1M request payload   | 23576 ms                             | ~24 ms                         |
  
  
## Building the PoP Token Using Private Key PEM String
The following Java JUnit test describes how to build the PoP using private key PEM string.  
  
```
package com.tmobile.oss.security.taap.poptoken.builder.demo;

import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import com.tmobile.oss.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;

public class PopTokenBuilderDemoWithPrivateKeyPemStringTest {

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void buildPopTokenWithPrivateKeyPemString() throws PopTokenBuilderException {

        String privateKeyPemString = "-----BEGIN PRIVATE KEY-----" + LINE_SEPARATOR //
                + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2ccmjG1gBJwTN" + LINE_SEPARATOR //
                + "slQJAEYmQYZl0j2LI+URPXCOjWj3hcmjYQPdfd+ZeCKuA8aUgXFox1xBdIxqAnY4" + LINE_SEPARATOR //
                + "8pW0MyMlwtyOiMpcnelzuKl9CqktbLSxdOUDo/wOd2d4lKnuvIHSKeoETfENroVM" + LINE_SEPARATOR //
                + "3Cm3CFJ8tmpQRjMYh4MBxZh2V3XClhES8t12DI+Lznr5BWvk8oIjRRs99Xu2n9Dy" + LINE_SEPARATOR //
                + "RoYal3trb+0ncdmr5EDhDE/sBC6MAk37UjyS8sty37+tbcgLkn42WISemSLnA4IO" + LINE_SEPARATOR //
                + "yiW6EZHcSTXj/vUCHLJjwDyihMCUWfA6NxLPlPFcLaD4o8DEg2VOa89rL9t1SoBo" + LINE_SEPARATOR //
                + "wsEhLn/5AgMBAAECggEBAI0tReOSMCpMIDpvyPliHeZShAZchsUZlJMfoO6eXGBV" + LINE_SEPARATOR //
                + "Ra/ITa5iTdk7DlLrlwmplLGIu0nnPxR1LThp9xAHFiaNQBCHp1e91j124qhgzILb" + LINE_SEPARATOR //
                + "AIPlOaX0igJDwWycVVboxeh0CKMmEOcOahYMs7bvmKzqlx/hAn7ztZt0ZMMGcJiO" + LINE_SEPARATOR //
                + "KLIUBVOjFoCeDoLgjvNrBduvHCnQ2CcJLnBxml7oRYc63ipBeJmC+aGjCIdKGtFK" + LINE_SEPARATOR //
                + "WRGiYrM4n5h4CKEnMTaZ+KAkJTmS43CBobDbp+rJbfpsGo7+xCt1VyjZfpMjF3zB" + LINE_SEPARATOR //
                + "oK8LywuFDddwopcMMkCHbFo7sM9HBqW7vyzgxlBZ5QECgYEA8f6XN2o9QV57H6GO" + LINE_SEPARATOR //
                + "5X0tCe5zdHt4NIHGYJfC3gVkduurMg8q/DBHBodFokp53OC48zOh6NzJOyhWacLq" + LINE_SEPARATOR //
                + "H6oSLQy2oSIBIXKC3Wt9yreOa3g69tQTN+CT7OT87KMvV0nYf7lXWTxjgMLEgClh" + LINE_SEPARATOR //
                + "0tDDls3+03oIQ4FpP7LBc6WhhRkCgYEAwQDmOtAYP51xuuVXl3Z0x9r6xfeIq/NG" + LINE_SEPARATOR //
                + "IqlVcq6tB+yWJ+YtVoysboyTcfJbGCPRMeQlrntfHSkdjMWb8R+xwt5c0eAmcL8m" + LINE_SEPARATOR //
                + "9tEtjHFa2QkqbKkQ3wRmS6KXJ8WJGY2opnVPwpWHpJn2qg01NkgQFfkjgUkWPSZx" + LINE_SEPARATOR //
                + "oauKcjiwTeECfx1NtwH+22wPBNnPtn4TqmCJf3GbgfLZxCvuNKqt/HxqDVEChTIE" + LINE_SEPARATOR //
                + "ppUjzErauecFT2Aj4HdSRQvk1pH4CGHNNmY+I99fPsPOGgq1+YWStKxO4tUA2VLq" + LINE_SEPARATOR //
                + "3v7Qu8/r8s+fIZhV2T31EheFfkYGvNHKdeTNDQ6OuHF0Okp8WvCmHekCgYEAtfW+" + LINE_SEPARATOR //
                + "GXa1Vcx/O+AbG54/bWjDgr7j6JE771PMTonmchEYY9d7qRyJONRp8kS2o2SpRqs8" + LINE_SEPARATOR //
                + "52pC+wAXbu+jHMpv0jPIOMpmE2f0OUBu+/im2PXuPHGMiWXhd697aLCwmBnZBc6V" + LINE_SEPARATOR //
                + "+vL05jeNuTcoktuP5tdzJOGeCNrkyLIsnZFajqECgYAGEbakt+8OpDxFVIFzPWGT" + LINE_SEPARATOR //
                + "f2KIeBYHX74JiJ3C0iGYvTiIO2cPuM3sSzUfx6+kmCqKioLueMW6BcAIy0WdELOh" + LINE_SEPARATOR //
                + "P1MaK10FQ12qFFrsnOZjVPoxZ4xVtzN3e4uCyc69xT2bAUpzoVKCMaCSRNv/unGk" + LINE_SEPARATOR //
                + "zHNmq7/VPITL5UgtZ5nk6g==" + LINE_SEPARATOR //
                + "-----END PRIVATE KEY-----" + LINE_SEPARATOR; //

        // STEP 1: Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), "/commerce/v1/orders"); // URL = https://api.t-mobile.com/commerce/v1/orders
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), "POST");
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}");

        // STEP 2: Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(privateKeyPemString) //
                .build();

        // verify the popToken has text
        assertTrue(StringUtils.isNotBlank(popToken));
    }
}
```

  
## Building the PoP Token Using Encrypted Private Key PEM String
The following Java JUnit test describes how to build the PoP using the encrypted private key PEM string.  
  
```
package com.tmobile.oss.security.taap.poptoken.builder.demo;

import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import com.tmobile.oss.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;

public class PopTokenBuilderDemoWithEncryptedPrivateKeyPemStringAndPasswordTest {

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void buildPopTokenWithAes256EncryptedPrivateKeyPemString() throws PopTokenBuilderException {

        /**
         * This encrypted private key has been created using the following commands.
         * 
         * // creates the private key in PKCS1 format <br>
         * <code>openssl genrsa -aes256 -passout pass:foobar -out private_key_aes256_with_password.pem 2048</code>
         * 
         * // converts the private key to PKCS8 format <br>
         * <code>openssl pkcs8 -topk8 -inform PEM -in private_key_aes256_with_password.pem -outform PEM -out private_key_aes256_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar</code>
         */
        String aes256EncryptedPrivateKeyPemString = "-----BEGIN ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR
                + "MIIE6TAbBgkqhkiG9w0BBQMwDgQIgHkFaWfpw/sCAggABIIEyFlXMsc8DSfsnWGc" + LINE_SEPARATOR
                + "bNdyFzp6rIFAuya2BCid2F+Xr6S1hq8bcO3ZZpg4jpDUqFhdF/+Q2qjTyPtmD8Fp" + LINE_SEPARATOR
                + "gxXTZVUW942WX+NlNY2n60GWiSIUw/iQG1Z5w8ArE/1K4bFq3zYyzxfoul2gEBJh" + LINE_SEPARATOR
                + "WcYyAW0DYh1ooeGEh+Sf3qttXj2E2BfCbAE42lGYb7PKSgrSPCxODeaiyHd6nCIy" + LINE_SEPARATOR
                + "i9S7rwDPtgrE4uHu8t0m8sTHlXllM/CdyNZaVcNWNRNMqmdtJmi9v5grqB9M1jpe" + LINE_SEPARATOR
                + "HTtXFjlpRgDOeY2T4JptGs9nt3N6lDdd+ufs4WBkJLh6b4i2fHCrf8K2ZMB6qwTk" + LINE_SEPARATOR
                + "IMf4OUUDmGPh9CI3t5xDZlLEhaZiQFsoJypYF8O2PBDTbrk2ZyMcKObNIZHVNfS0" + LINE_SEPARATOR
                + "asvMjg4jbA0qhvsujf+t3rrw89fdQLQrGBR0zQwAnXPXI1biFupA4iAKjoD3BtHL" + LINE_SEPARATOR
                + "46tv20L59T6uV1NAmoqCvNOgf+Rkxe/TXLwE7ungE2uxIW5F+3kNlMNr1Olom59I" + LINE_SEPARATOR
                + "GVT2T8SOoRjavvz676vYWcJY8Vd4usECEUCJN/divDoHn3LS4eLa8Q9dYf4O15oU" + LINE_SEPARATOR
                + "DGuJQgGiNeFeGqgOJkCsOyWw1uZJDcjxrFuzPO0SBPZKIH/Jsraw9D+5u0g/VDqI" + LINE_SEPARATOR
                + "8o/nLt6YPAhGY2PBO0XOm2VO+dbVPMNQq/QZcJ3pw+MLhLufBwCya89ivUo2ybsb" + LINE_SEPARATOR
                + "u/XtJDKse0kDpbYqL/c+xCVXMQl6PJh2CmSpqLGCsFbf0Dhiw7gYKpChsTXycwnP" + LINE_SEPARATOR
                + "GyhmHltWzPC5bS1NSMMS1dirFMKnM2cPUzlzjeTWOOh19j1nyHADmdCaKXxHuToX" + LINE_SEPARATOR
                + "3j+5glQl4VA+rZyCvZKUToxedEZ/IADetZSbRS5GhTWHE2QPGEjjuSypVU1DUmmk" + LINE_SEPARATOR
                + "hNQIExEdQ7mQRPSwwcVbxFY7sfvLZrNTk8okuKUNVAU1ICwZlWuvKChYNmiuXmkg" + LINE_SEPARATOR
                + "sG+eqiPaUJC0y+FL3LU3e/bd/Zbf3jK16wtcylBbVUa16TPe7f6NrcxQ5io+53SS" + LINE_SEPARATOR
                + "7f5puvRaBD9WUT2YO2RFysOgZHwaX5k2Qyl0EDR7R5kqWzkVAh0s59AaIs/lmdaA" + LINE_SEPARATOR
                + "S5mJD9nE/osZCp37bhHzB17NR8By91HPlED2ZngpYxEzYCLs9AVk2SlWId9tlITW" + LINE_SEPARATOR
                + "6CzFe7ell9sZMrNn/x6iyDTh8MJlk+6J5WQvtfniU0tGhzhWxGgZj1tvneaZZxRc" + LINE_SEPARATOR
                + "rNCbxaIQnA0cX9fp4LRdcCRZ2XKVWUoweJYxBYjRCm4ziJnj+tbtGHyRNNj1sA9Z" + LINE_SEPARATOR
                + "cJnWMd2+M/SuI52BdIgIU+wXmRURYuEl1u+ZoeAjETHNaPPGvvDgnayFgeRPpA6P" + LINE_SEPARATOR
                + "tdnHavYrzw6/HevkgxhLFZM3jjS4hWo6TyLjhGl+BWZcnX9wM5hHQOCN2sbUaPmi" + LINE_SEPARATOR
                + "wVY7QimfAD7H7G2blE+RUV7crgFT/mhDG/VZJWjU6x92NC7lMZPQbL8UPIync88T" + LINE_SEPARATOR
                + "44fNv9GtMfUOuQgcawDwlIJrIuP32kvgVlKxA4VMUM9Icw6uy0eCbFPVWPjDPJ31" + LINE_SEPARATOR
                + "B4hwcjie25G6oD/kMx/2zxs3zt0ST2hfUQ6jli98QMOZbdAKMWJd1nq8LDDdUpUa" + LINE_SEPARATOR //
                + "chcblDYmEVmup0H/Nw==" + LINE_SEPARATOR //
                + "-----END ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR; //
        String privateKeyPassword = "foobar";

        // STEP 1: Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), "/commerce/v1/orders"); // URL = https://api.t-mobile.com/commerce/v1/orders
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), "POST");
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}");

        // STEP 2: Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(aes256EncryptedPrivateKeyPemString, privateKeyPassword) //
                .build();

        // verify the popToken has text
        assertTrue(StringUtils.isNotBlank(popToken));
    }

    @Test
    public void buildPopTokenWithDes3EncryptedPrivateKeyPemString() throws PopTokenBuilderException {

        /**
         * This encrypted private key has been created using the following commands.
         * 
         * // creates the private key in PKCS1 format <br>
         * <code>openssl genrsa -des3 -passout pass:foobar -out private_key_des3_with_password.pem 2048</code>
         * 
         * // converts the private key to PKCS8 format <br>
         * <code>openssl pkcs8 -topk8 -inform PEM -in private_key_des3_with_password.pem -outform PEM -out private_key_des3_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar</code>
         */
        String des3EncryptedPrivateKeyPemString = "-----BEGIN ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR
                + "MIIE6TAbBgkqhkiG9w0BBQMwDgQI05SLGK2TADYCAggABIIEyEqVOM/eZZurtlhO" + LINE_SEPARATOR
                + "Kszf/jq7LaGlMVavArkhv9DrsLj3rZm5WsDQc9eB3qLDRZuUZZ6ak23mckbl1hId" + LINE_SEPARATOR
                + "iE6gjxbeLXYOf2zr6R8ESgktO7SOp2dEvxChENIKPd0boNyJgx00yKA2PaHyVeEA" + LINE_SEPARATOR
                + "tHate0Q3SJNAPa8qLiHT2eJ3nA08yHvoaiROya9t8a5xz1qb7yJKmeD/qEw5RoPD" + LINE_SEPARATOR
                + "Gbj9Q4dVaqNFSxWRHb0bLRrklHn/9klY9vmsPGaluuIKpzo4Cg5uBYtyks0S4Xab" + LINE_SEPARATOR
                + "u7s6QvXBiJXQLu4R7c55rnY17CWg1gfs/NnXquLlStDqslPmjNymRFcyEPFwqtM9" + LINE_SEPARATOR
                + "ZNjeRHYcaSnI+zEz6JqZMU/IxCWDgmZmr3f95a3q7JYwT386gvBouSSCOVbckprB" + LINE_SEPARATOR
                + "tCsBS3iwsNaxt/dGdTNfArn97zQjTM9QWkZ+6aC7uMtU+zXlB9nxSg1LB5cPRmvc" + LINE_SEPARATOR
                + "wvwBjV0cB3uQt16ASq7J0rB8Mr3o6v/RlKHdkGX6h33kMewzT1FMQvN5m9ZB4Pne" + LINE_SEPARATOR
                + "IjA9VuLlPUAKnMsRD+EogntCGoQUl9jOkNURJpql/rg3NtS2EUAOFzG4xrQYK+re" + LINE_SEPARATOR
                + "mesOPSg0hE/Inj8MaHFPTL7BI3o9ZYe9jxhAdZVQEz5qOxq0NlV1WGaGwJKiViM7" + LINE_SEPARATOR
                + "7q4JtZcJZJ4Z5huQ13VcgxGqsAjuOAuKT3jg7ccQf5ku28fhklQ5/NtBtHm0LW3J" + LINE_SEPARATOR
                + "9b+Wfhty/CsBVplu3Z9BFPxqBymRdULUhmN2O5rVBLVE0EBGa67IBElTS69upY24" + LINE_SEPARATOR
                + "RTrm/uPsQCT7hgxt/mONL6lmB+sCPIfEoyPIXvZNgc3vR9K1FzAoGkHIVq7RzIpE" + LINE_SEPARATOR
                + "09TxPUXiaCK6rad7qhNs2cpHn5GJzzUCNVV7ooOpvoFhjFf0ZLuLxh+zo/e5Nvrl" + LINE_SEPARATOR
                + "OS9IgOCMHdzBWXS261UocDEZ+WvBSQOf1uNqI+NJN6O4XQxK2EgXjozSUjS3DvPt" + LINE_SEPARATOR
                + "fFiwv32SgO9juN5KFzwDQzwhyAIVrMZ+R/qiRDPJSPiteYGfGuxngGwCQDSGvH2a" + LINE_SEPARATOR
                + "9BGEvP52Spil0VG3sXT57Io8VuJBWKlZqt0bqGZJ9Rtpz6QQKPBrYp8CClAWU0vT" + LINE_SEPARATOR
                + "+HSi7OkKSt6FFHNdEa4bxfomCdT3RtCbBXhOeZMTzvj5Kt6QQHPtPjJAFYk4G2DL" + LINE_SEPARATOR
                + "MldIsi8wZ3vFnTTSOvhvUhZSSJpE8FmUhblPwSwUrvW75Yn2+PIKABd5g7Tw574J" + LINE_SEPARATOR
                + "ytc6MU4+pHxNIr594noVUZffiXfdg3g7x0T8ZuLKjRlJnlTheZdrot1qe8Yb6bX+" + LINE_SEPARATOR
                + "lgf++lfxxBTONjrADS5R/hznc4ojGSOY5wv5MB8BVkANQx2sRWv5EkTUszoxLkrN" + LINE_SEPARATOR
                + "SSwIdWCHmVSzMThi6ir3ouxCeBcMTDrWYNku4yQavPh/+ObMSQN/MJBdCDzFgd1H" + LINE_SEPARATOR
                + "6VAsqPZp7tyaBYKVkJwLNOQ/5THMWylm27y12Q8c44kjPGxVAtSJOuIR/xxywW0c" + LINE_SEPARATOR
                + "Eog0+FH727JvoXM+N3v9nfDEBoR6RbJjmkjv08vAh1nJjcmPQ2JLaSMdegsorep+" + LINE_SEPARATOR
                + "lByzS/bl3Kwgu0MAaQwGlH6LhyvhBOKUMm2mbdBVNu9uBfGeqvIsGiIw8E87yT6O" + LINE_SEPARATOR //
                + "Ybza3fEAAjBUC5gPdQ==" + LINE_SEPARATOR //
                + "-----END ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR; //
        String privateKeyPassword = "foobar";

        // STEP 1: Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), "/commerce/v1/orders"); // URL = https://api.t-mobile.com/commerce/v1/orders
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), "POST");
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}");

        // STEP 2: Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(des3EncryptedPrivateKeyPemString, privateKeyPassword) //
                .build();

        // verify the popToken has text
        assertTrue(StringUtils.isNotBlank(popToken));
    }
}
```

  
## Building the PoP Token Using RSAPrivateKey
The following Java JUnit test describes how to build the PoP using RSAPrivateKey.
  
```
package com.tmobile.oss.security.taap.poptoken.builder.demo;

import static org.junit.Assert.assertTrue;

import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import com.tmobile.oss.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;
import com.tmobile.oss.security.taap.poptoken.builder.utils.PopTokenBuilderUtils;

public class PopTokenBuilderDemoWithRsaPrivateKeyTest {

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void buildPopTokenWithRsaPrivateKey() throws PopTokenBuilderException {

        String privateKeyPemString = "-----BEGIN PRIVATE KEY-----" + LINE_SEPARATOR //
                + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2ccmjG1gBJwTN" + LINE_SEPARATOR //
                + "slQJAEYmQYZl0j2LI+URPXCOjWj3hcmjYQPdfd+ZeCKuA8aUgXFox1xBdIxqAnY4" + LINE_SEPARATOR //
                + "8pW0MyMlwtyOiMpcnelzuKl9CqktbLSxdOUDo/wOd2d4lKnuvIHSKeoETfENroVM" + LINE_SEPARATOR //
                + "3Cm3CFJ8tmpQRjMYh4MBxZh2V3XClhES8t12DI+Lznr5BWvk8oIjRRs99Xu2n9Dy" + LINE_SEPARATOR //
                + "RoYal3trb+0ncdmr5EDhDE/sBC6MAk37UjyS8sty37+tbcgLkn42WISemSLnA4IO" + LINE_SEPARATOR //
                + "yiW6EZHcSTXj/vUCHLJjwDyihMCUWfA6NxLPlPFcLaD4o8DEg2VOa89rL9t1SoBo" + LINE_SEPARATOR //
                + "wsEhLn/5AgMBAAECggEBAI0tReOSMCpMIDpvyPliHeZShAZchsUZlJMfoO6eXGBV" + LINE_SEPARATOR //
                + "Ra/ITa5iTdk7DlLrlwmplLGIu0nnPxR1LThp9xAHFiaNQBCHp1e91j124qhgzILb" + LINE_SEPARATOR //
                + "AIPlOaX0igJDwWycVVboxeh0CKMmEOcOahYMs7bvmKzqlx/hAn7ztZt0ZMMGcJiO" + LINE_SEPARATOR //
                + "KLIUBVOjFoCeDoLgjvNrBduvHCnQ2CcJLnBxml7oRYc63ipBeJmC+aGjCIdKGtFK" + LINE_SEPARATOR //
                + "WRGiYrM4n5h4CKEnMTaZ+KAkJTmS43CBobDbp+rJbfpsGo7+xCt1VyjZfpMjF3zB" + LINE_SEPARATOR //
                + "oK8LywuFDddwopcMMkCHbFo7sM9HBqW7vyzgxlBZ5QECgYEA8f6XN2o9QV57H6GO" + LINE_SEPARATOR //
                + "5X0tCe5zdHt4NIHGYJfC3gVkduurMg8q/DBHBodFokp53OC48zOh6NzJOyhWacLq" + LINE_SEPARATOR //
                + "H6oSLQy2oSIBIXKC3Wt9yreOa3g69tQTN+CT7OT87KMvV0nYf7lXWTxjgMLEgClh" + LINE_SEPARATOR //
                + "0tDDls3+03oIQ4FpP7LBc6WhhRkCgYEAwQDmOtAYP51xuuVXl3Z0x9r6xfeIq/NG" + LINE_SEPARATOR //
                + "IqlVcq6tB+yWJ+YtVoysboyTcfJbGCPRMeQlrntfHSkdjMWb8R+xwt5c0eAmcL8m" + LINE_SEPARATOR //
                + "9tEtjHFa2QkqbKkQ3wRmS6KXJ8WJGY2opnVPwpWHpJn2qg01NkgQFfkjgUkWPSZx" + LINE_SEPARATOR //
                + "oauKcjiwTeECfx1NtwH+22wPBNnPtn4TqmCJf3GbgfLZxCvuNKqt/HxqDVEChTIE" + LINE_SEPARATOR //
                + "ppUjzErauecFT2Aj4HdSRQvk1pH4CGHNNmY+I99fPsPOGgq1+YWStKxO4tUA2VLq" + LINE_SEPARATOR //
                + "3v7Qu8/r8s+fIZhV2T31EheFfkYGvNHKdeTNDQ6OuHF0Okp8WvCmHekCgYEAtfW+" + LINE_SEPARATOR //
                + "GXa1Vcx/O+AbG54/bWjDgr7j6JE771PMTonmchEYY9d7qRyJONRp8kS2o2SpRqs8" + LINE_SEPARATOR //
                + "52pC+wAXbu+jHMpv0jPIOMpmE2f0OUBu+/im2PXuPHGMiWXhd697aLCwmBnZBc6V" + LINE_SEPARATOR //
                + "+vL05jeNuTcoktuP5tdzJOGeCNrkyLIsnZFajqECgYAGEbakt+8OpDxFVIFzPWGT" + LINE_SEPARATOR //
                + "f2KIeBYHX74JiJ3C0iGYvTiIO2cPuM3sSzUfx6+kmCqKioLueMW6BcAIy0WdELOh" + LINE_SEPARATOR //
                + "P1MaK10FQ12qFFrsnOZjVPoxZ4xVtzN3e4uCyc69xT2bAUpzoVKCMaCSRNv/unGk" + LINE_SEPARATOR //
                + "zHNmq7/VPITL5UgtZ5nk6g==" + LINE_SEPARATOR //
                + "-----END PRIVATE KEY-----" + LINE_SEPARATOR; //

        // STEP 1: Convert private key PEM string to RSAPrivateKey
        RSAPrivateKey rsaPrivateKey = PopTokenBuilderUtils.keyPemStringToRsaPrivateKey(privateKeyPemString);

        // STEP 2: Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), "/commerce/v1/orders"); // URL = https://api.t-mobile.com/commerce/v1/orders
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), "POST");
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}");

        // STEP 3: Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(rsaPrivateKey) //
                .build();

        // verify the popToken has text
        assertTrue(StringUtils.isNotBlank(popToken));
    }
}
```

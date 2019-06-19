package com.tmobile.oss.security.taap.poptoken.builder.demo;

import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.oss.security.taap.poptoken.builder.PopEhtsKey;
import com.tmobile.oss.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;

public class PopTokenBuilderDemoWithEncryptedPrivateKeyPemStringAndPasswordNoRequestPayloadPerfTest {

    private static final Logger logger = LoggerFactory
            .getLogger(PopTokenBuilderDemoWithEncryptedPrivateKeyPemStringAndPasswordNoRequestPayloadPerfTest.class);

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

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < 1000; i++) {
            buildPopTokenWithEncryptedPrivateKeyPemString(aes256EncryptedPrivateKeyPemString, privateKeyPassword);
        }

        long actualProcessingTime = System.currentTimeMillis() - startTime;
        long expectedProcessingTime = 20000L;

        logger.info("buildPopTokenWithAes256EncryptedPrivateKeyPemString -> actual processing time: " + actualProcessingTime + " ms"); //
        assertTrue("Should not have taken more than " + expectedProcessingTime
                + " millis for 1000 validations, actual processing time: " + actualProcessingTime,
                (actualProcessingTime <= expectedProcessingTime)); //
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

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < 1000; i++) {
            buildPopTokenWithEncryptedPrivateKeyPemString(des3EncryptedPrivateKeyPemString, privateKeyPassword);
        }

        long actualProcessingTime = System.currentTimeMillis() - startTime;
        long expectedProcessingTime = 20000L;

        logger.info("buildPopTokenWithDes3EncryptedPrivateKeyPemString -> actual processing time: " + actualProcessingTime + " ms"); //
        assertTrue("Should not have taken more than " + expectedProcessingTime
                + " millis for 1000 validations, actual processing time: " + actualProcessingTime,
                (actualProcessingTime <= expectedProcessingTime)); //
    }

    // ===== helper methods ===== //
    private void buildPopTokenWithEncryptedPrivateKeyPemString(String encryptedPrivateKeyPemString, String privateKeyPassword)
            throws PopTokenBuilderException {

        // STEP 1: Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), "/commerce/v1/orders"); // URL = https://api.t-mobile.com/commerce/v1/orders
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), "post");
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), "{\"orderId\": 100, \"product\": \"Mobile Phone\"}");

        // STEP 2: Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(encryptedPrivateKeyPemString, privateKeyPassword) //
                .build();

        // verify the popToken has text
        assertTrue(StringUtils.isNotBlank(popToken));
    }
}

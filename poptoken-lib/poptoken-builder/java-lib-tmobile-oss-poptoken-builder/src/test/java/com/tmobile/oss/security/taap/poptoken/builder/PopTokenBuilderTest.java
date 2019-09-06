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

package com.tmobile.oss.security.taap.poptoken.builder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.tmobile.oss.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;
import com.tmobile.oss.security.taap.poptoken.builder.testutils.PopTokenBuilderTestUtils;

public class PopTokenBuilderTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenBuilderTest.class);

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void buildPopToken__withPrivateKeyPemString__successfullyBuildsPopToken() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        byte[] privateKeyBytes = rsaPrivateKey.getEncoded();
        String privateKeyPemString = PopTokenBuilderTestUtils.generatePrivateKeyPemString(privateKeyBytes);

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        // perform an action
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(privateKeyPemString) //
                .build();

        // verify the results
        assertTrue(StringUtils.isNotBlank(popToken));

        DecodedJWT signedPopToken = JWT.decode(popToken);
        assertEquals("RS256", signedPopToken.getAlgorithm());
        assertNotNull("IssuedAt (iat) is null", signedPopToken.getIssuedAt());
        assertNotNull("ExpireAt (exp) is null", signedPopToken.getExpiresAt());
        assertEquals("Token validity duration is invalid", PopTokenBuilder.POP_TOKEN_VALIDITY_DURATION_IN_MILLIS,
                ((signedPopToken.getExpiresAt().getTime() - signedPopToken.getIssuedAt().getTime())));
        assertEquals("1", signedPopToken.getClaim("v").asString());
        assertNotNull("Unique identifer (jti) is null", signedPopToken.getClaim("jti").asString());

        // verify with the matching public key, this should succeed
        final Algorithm matchingPublicKeyAlgorithm = buildRsa256Algorithm(rsaPublicKey);
        try {
            JWT.require(matchingPublicKeyAlgorithm) //
                    .build() //
                    .verify(popToken); //
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("Should not have thrown an exception");
        }
    }

    @Test
    public void buildPopToken__withAes256EncryptedPrivateKeyPemStringAndPassword__successfullyBuildsPopToken() throws Exception {

        // setup the data
        /**
         * This encrypted private key has been created using the following commands.
         * 
         * // creates the private key in PKCS1 format <br>
         * <code>openssl genrsa -aes256 -passout pass:foobar -out private_key_aes256_with_password.pem 2048</code>
         * 
         * // converts the private key to PKCS8 format <br>
         * <code>openssl pkcs8 -topk8 -inform PEM -in private_key_aes256_with_password.pem -outform PEM -out private_key_aes256_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar</code>
         * 
         * // creates the public key in PKCS8 format
         * <code>openssl rsa -in private_key_aes256_with_password.pem -passin pass:foobar -outform PEM -pubout -out public_key_for_pk_aes256_with_password.pem</code>
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
        String publicKeyPemString = "-----BEGIN PUBLIC KEY-----" + LINE_SEPARATOR
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr+0/FhalG0k9q1f7z3+4" + LINE_SEPARATOR
                + "nPGBzomaccA42jjmz2fuZMECD1QLMHpmdX4dE/bnudwWV8CEpYgKMi5CqbWfpihe" + LINE_SEPARATOR
                + "ahnIhPiE7IsIlln/cTX9b3KUxiVefSCGrXAUxA8IqL30I80ssPj3g8e73NZZIagJ" + LINE_SEPARATOR
                + "JF0vz1Etfe6JNW2pTFLMgGh/QkDZD5G/QgO4auyNBsfWyqkH2IvQrS7b/xMRX46t" + LINE_SEPARATOR
                + "7wTaG0AmsPR+uUYVGJKuQRLqtZWgv7jVAqAya08trG68j9eZ8ysUeMDIwLwS5vBf" + LINE_SEPARATOR
                + "fdIMCYzsgar+SR9K/7pgL/6pW9zcS+tARnlOpKVVkPhJ7wM1NJENgkikt37qvJIY" + LINE_SEPARATOR //
                + "qwIDAQAB" + LINE_SEPARATOR //
                + "-----END PUBLIC KEY-----" + LINE_SEPARATOR; //

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        // perform an action
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(aes256EncryptedPrivateKeyPemString, privateKeyPassword) //
                .build();

        // verify the results
        assertTrue(StringUtils.isNotBlank(popToken));

        DecodedJWT signedPopToken = JWT.decode(popToken);
        assertEquals("RS256", signedPopToken.getAlgorithm());
        assertNotNull("IssuedAt (iat) is null", signedPopToken.getIssuedAt());
        assertNotNull("ExpireAt (exp) is null", signedPopToken.getExpiresAt());
        assertEquals("Token validity duration is invalid", PopTokenBuilder.POP_TOKEN_VALIDITY_DURATION_IN_MILLIS,
                ((signedPopToken.getExpiresAt().getTime() - signedPopToken.getIssuedAt().getTime())));
        assertEquals("1", signedPopToken.getClaim("v").asString());
        assertNotNull("Unique identifer (jti) is null", signedPopToken.getClaim("jti").asString());

        // verify with the matching public key, this should succeed
        final RSAPublicKey rsaPublicKey = pemKeyStringToRsaPublicKey(publicKeyPemString);

        final Algorithm matchingPublicKeyAlgorithm = buildRsa256Algorithm(rsaPublicKey);
        try {
            JWT.require(matchingPublicKeyAlgorithm) //
                    .build() //
                    .verify(popToken); //
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("Should not have thrown an exception");
        }
    }

    @Test
    public void buildPopToken__withDes3EncryptedPrivateKeyPemStringAndPassword__successfullyBuildsPopToken() throws Exception {

        // setup the data
        /**
         * This encrypted private key has been created using the following commands.
         * 
         * // creates the private key in PKCS1 format <br>
         * <code>openssl genrsa -des3 -passout pass:foobar -out private_key_des3_with_password.pem 2048</code>
         * 
         * // converts the private key to PKCS8 format <br>
         * <code>openssl pkcs8 -topk8 -inform PEM -in private_key_des3_with_password.pem -outform PEM -out private_key_des3_with_password_pkcs8.pem -passin pass:foobar -passout pass:foobar</code>
         * 
         * // creates the public key in PKCS8 format
         * <code>openssl rsa -in private_key_des3_with_password.pem -passin pass:foobar -outform PEM -pubout -out public_key_for_pk_des3_with_password.pem</code>
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
        String publicKeyPemString = "-----BEGIN PUBLIC KEY-----" + LINE_SEPARATOR
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxLXRDDOyszizV8lcs922" + LINE_SEPARATOR
                + "vF1jphS95C/aAiQnyRYunR3mCeyGkpr2i7ltuYCabU4yNSa25wIo86b3VNWM4nmp" + LINE_SEPARATOR
                + "shNNTR742jWX2OvKst6o19AFQhftaptJqEpsCT2aGYuzB9OOaYKuqycA0frmmjJH" + LINE_SEPARATOR
                + "zW96VG9aCXggTVSAaIGMunpauatecJO9nrgAWoNNlrXMNVWhvAdjd0g+8jeM0cMM" + LINE_SEPARATOR
                + "UO9LTkYG5ZtHRNb3GnXOuXNkC5qRROJp62DIgOLHNICmMQl9hx/pjns32JU0X112" + LINE_SEPARATOR
                + "/e4WfJKRp7xt7ie5e3DDDe9cSB907VTJIiLQeOWsDhLS7Luj4qi9yRMnhLm9E86P" + LINE_SEPARATOR //
                + "DwIDAQAB" + LINE_SEPARATOR //
                + "-----END PUBLIC KEY-----"; //

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        // perform an action
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(des3EncryptedPrivateKeyPemString, privateKeyPassword) //
                .build();

        // verify the results
        assertTrue(StringUtils.isNotBlank(popToken));

        DecodedJWT signedPopToken = JWT.decode(popToken);
        assertEquals("RS256", signedPopToken.getAlgorithm());
        assertNotNull("IssuedAt (iat) is null", signedPopToken.getIssuedAt());
        assertNotNull("ExpireAt (exp) is null", signedPopToken.getExpiresAt());
        assertEquals("Token validity duration is invalid", PopTokenBuilder.POP_TOKEN_VALIDITY_DURATION_IN_MILLIS,
                ((signedPopToken.getExpiresAt().getTime() - signedPopToken.getIssuedAt().getTime())));
        assertEquals("1", signedPopToken.getClaim("v").asString());
        assertNotNull("Unique identifer (jti) is null", signedPopToken.getClaim("jti").asString());

        // verify with the matching public key, this should succeed
        final RSAPublicKey rsaPublicKey = pemKeyStringToRsaPublicKey(publicKeyPemString);
        final Algorithm matchingPublicKeyAlgorithm = buildRsa256Algorithm(rsaPublicKey);
        try {
            JWT.require(matchingPublicKeyAlgorithm) //
                    .build() //
                    .verify(popToken); //
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("Should not have thrown an exception");
        }
    }

    @Test
    public void buildPopToken__withRsaPrivateKey__successfullyBuildsPopToken() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        // perform an action
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(rsaPrivateKey) //
                .build();

        // verify the results
        assertTrue(StringUtils.isNotBlank(popToken));

        DecodedJWT signedPopToken = JWT.decode(popToken);
        assertEquals("RS256", signedPopToken.getAlgorithm());
        assertNotNull("IssuedAt (iat) is null", signedPopToken.getIssuedAt());
        assertNotNull("ExpireAt (exp) is null", signedPopToken.getExpiresAt());
        assertEquals("Token validity duration is invalid", PopTokenBuilder.POP_TOKEN_VALIDITY_DURATION_IN_MILLIS,
                ((signedPopToken.getExpiresAt().getTime() - signedPopToken.getIssuedAt().getTime())));
        assertEquals("1", signedPopToken.getClaim("v").asString());
        assertNotNull("Unique identifer (jti) is null", signedPopToken.getClaim("jti").asString());

        // verify with the matching public key, this should succeed
        final Algorithm matchingPublicKeyAlgorithm = buildRsa256Algorithm(rsaPublicKey);
        try {
            JWT.require(matchingPublicKeyAlgorithm) //
                    .build() //
                    .verify(popToken); //
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            fail("Should not have thrown an exception");
        }
    }

    @Test
    public void buildPopToken__verifySignatureUsingNonMatchingPublicKey__throwsAnException() throws Exception {

        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        // perform an action
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(rsaPrivateKey) //
                .build();

        // verify the results
        assertTrue(StringUtils.isNotBlank(popToken));

        DecodedJWT signedPopToken = JWT.decode(popToken);
        assertEquals("RS256", signedPopToken.getAlgorithm());
        assertNotNull("IssuedAt (iat) is null", signedPopToken.getIssuedAt());
        assertNotNull("ExpireAt (exp) is null", signedPopToken.getExpiresAt());
        assertEquals("Token validity duration is invalid", PopTokenBuilder.POP_TOKEN_VALIDITY_DURATION_IN_MILLIS,
                ((signedPopToken.getExpiresAt().getTime() - signedPopToken.getIssuedAt().getTime())));
        assertEquals("1", signedPopToken.getClaim("v").asString());
        assertNotNull("Unique identifer (jti) is null", signedPopToken.getClaim("jti").asString());

        // verify with the different public key, this should not succeed
        RSAPublicKey nonMatchingPublicKey = (RSAPublicKey) PopTokenBuilderTestUtils.createNewRsaKeyPair().getPublic();
        final Algorithm nonMatchingPublicKeyAlogrithm = buildRsa256Algorithm(nonMatchingPublicKey);
        try {
            JWT.require(nonMatchingPublicKeyAlogrithm) //
                    .build() //
                    .verify(popToken); //
            fail("Should have thrown an exception");
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals("The Token's Signature resulted invalid when verified using the Algorithm: SHA256withRSA", ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapIsNotSpecified__throwsPopTokenBuilderException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .signWith(rsaPrivateKey) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapContainsEmptyKey__throwsAnException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("   ", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .signWith(rsaPrivateKey) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapContainsNullKey__throwsAnException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put(null, "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .signWith(rsaPrivateKey) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapContainsEmptyValue__throwsAnException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "   ");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .signWith(rsaPrivateKey) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapContainsNullValue__throwsAnException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", null);
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .signWith(rsaPrivateKey) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            // validate the results
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapIsEmpty__throwsPopTokenBuilderException() throws Exception {
        // setup the data
        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .signWith(rsaPrivateKey) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals(
                    "The ehtsKeyValueMap should not be null or empty and should not contain any null or empty ehts keys or values",
                    ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__ehtsKeyValueMapContainsMoreThan100Entries__throwsPopTokenBuilderException() throws Exception {
        // setup the data
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        for (int index = 0; index < 101; index++) {
            ehtsKeyValueMap.put("ehts-key-" + index, "ehts-value-" + index);
        }

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals("The ehtsKeyValueMap should not contain more than 100 entries", ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__privateKeyNotSpecified__throwsPopTokenBuilderException() throws Exception {
        // setup the data
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals("Either rsaPrivateKey or rsaPrivateKeyPemString should be provided to sign the PoP token", ex.getMessage());
        }
    }

    @Test
    public void buildPopToken__bothRsaPrivateKeyAndPrivateKeyPemStringSpecified__throwsPopTokenBuilderException() throws Exception {
        // setup the data

        KeyPair rsaKeyPair = PopTokenBuilderTestUtils.createNewRsaKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        byte[] privateKeyBytes = PopTokenBuilderTestUtils.createNewRsaPrivateKey().getEncoded();
        String privateKeyPemString = PopTokenBuilderTestUtils.generatePrivateKeyPemString(privateKeyBytes);

        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");

        try {
            // perform an action
            PopTokenBuilder.newInstance() //
                    .setEhtsKeyValueMap(ehtsKeyValueMap) //
                    .signWith(rsaPrivateKey) //
                    .signWith(privateKeyPemString) //
                    .build();
            fail("Should have thrown PopTokenBuilderException");
        } catch (Exception ex) {
            logger.error("Error occurred while executing the test case, error: " + ex.toString(), ex);
            assertEquals(PopTokenBuilderException.class, ex.getClass());
            assertEquals("Either only rsaPrivateKey or only rsaPrivateKeyPemString should be provided to sign the PoP token",
                    ex.getMessage());
        }
    }

    // ===== helper methods ===== //

    private Algorithm buildRsa256Algorithm(RSAPublicKey rsaPublicKey) {
        Algorithm rsa256Algorithm = Algorithm.RSA256(new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return rsaPublicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                throw new NotImplementedException("The getPrivateKey method is not implemented");
            }

            @Override
            public String getPrivateKeyId() {
                throw new NotImplementedException("The getPrivateKeyId method is not implemented");
            }
        });
        return rsa256Algorithm;
    }

    private RSAPublicKey pemKeyStringToRsaPublicKey(String publicKeyPemString)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        publicKeyPemString = publicKeyPemString.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPemString = publicKeyPemString.replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyPemString));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
        return rsaPublicKey;
    }
}

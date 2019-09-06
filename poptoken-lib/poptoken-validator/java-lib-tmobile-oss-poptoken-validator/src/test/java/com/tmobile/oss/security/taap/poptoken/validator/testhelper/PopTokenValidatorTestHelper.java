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

package com.tmobile.oss.security.taap.poptoken.validator.testhelper;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.NotImplementedException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class PopTokenValidatorTestHelper {

    public static String createPopToken(LinkedHashMap<String, String> ehtsKeyValueMap, Date tokenIssuedAtDate,
            int tokenValidForSeconds, RSAPrivateKey rsaPrivateKey) {

        return JWT.create() //
                .withClaim("ehts", buildEhtsString(ehtsKeyValueMap)) //
                .withClaim("edts", calculateEdtsSha256Base64Hash(ehtsKeyValueMap)) //
                .withClaim("jti", UUID.randomUUID().toString()) //
                .withClaim("v", "1") //
                .withIssuedAt(tokenIssuedAtDate) //
                .withExpiresAt(new Date(tokenIssuedAtDate.getTime() + (tokenValidForSeconds * 1000))) //
                .sign(buildRsa256Algorithm(rsaPrivateKey, null)); //
    }

    public static KeyPair createRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static RSAPublicKey createNewRsaPublicKey() throws NoSuchAlgorithmException {
        return (RSAPublicKey) createRsaKeyPair().getPublic();
    }

    public static String generatePublicKeyPemString(byte[] keyFileBytes) throws IOException {
        return generateKeyPemString("PUBLIC KEY", keyFileBytes);
    }

    public static String generateRsaPublicKeyPemString(byte[] keyFileBytes) throws IOException {
        return generateKeyPemString("RSA PUBLIC KEY", keyFileBytes);
    }

    public static String generatePrivateKeyPemString(byte[] keyFileBytes) throws IOException {
        return generateKeyPemString("PRIVATE KEY", keyFileBytes);
    }

    public static String generateRsaPrivateKeyPemString(byte[] keyFileBytes) throws IOException {
        return generateKeyPemString("RSA PRIVATE KEY", keyFileBytes);
    }

    public static String generateKeyPemString(String type, byte[] keyFileBytes) throws IOException {
        StringBuilder privateKeyPemStringBuilder = new StringBuilder();
        privateKeyPemStringBuilder.append("-----BEGIN " + type + "-----");
        privateKeyPemStringBuilder.append(Base64.encodeBase64String(keyFileBytes));
        privateKeyPemStringBuilder.append("-----END " + type + "-----");
        return privateKeyPemStringBuilder.toString();
    }

    public static String createRequestPayload(int size) {
        StringBuilder payloadBuilder = new StringBuilder();
        payloadBuilder.append("{");
        int index = 1;
        while (payloadBuilder.length() < size) {
            String key = "key-" + index;
            String value = "value-" + index;
            payloadBuilder.append("\"" + key + "\"" + ":" + "\"" + value + "\"");
            index++;
        }
        payloadBuilder.append("}");
        return payloadBuilder.toString();
    }

    // ===== static helper methods ===== //

    private static String buildEhtsString(LinkedHashMap<String, String> ehtsKeyValueMap) {

        StringBuilder ehtsStringBuilder = new StringBuilder();
        for (String ehtsKey : ehtsKeyValueMap.keySet()) {
            if (ehtsStringBuilder.length() > 0) {
                ehtsStringBuilder.append(";");
            }
            ehtsStringBuilder.append(ehtsKey);
        }
        return ehtsStringBuilder.toString();
    }

    private static String calculateEdtsSha256Base64Hash(Map<String, String> ehtsKeyValueMap) {
        StringBuilder stringToHashBuilder = new StringBuilder();
        for (Entry<String, String> ehtsKeyValueEntry : ehtsKeyValueMap.entrySet()) {
            stringToHashBuilder.append(ehtsKeyValueEntry.getValue());
        }
        String stringToHash = stringToHashBuilder.toString();
        return sha256Base64UrlSafeString(stringToHash);
    }

    private static String sha256Base64UrlSafeString(String stringToHash) {
        byte[] sha256Digest = DigestUtils.sha256(stringToHash);
        return Base64.encodeBase64URLSafeString(sha256Digest);
    }

    private static Algorithm buildRsa256Algorithm(RSAPrivateKey rsaPrivateKey, String privateKeyId) {
        Algorithm algorithm = Algorithm.RSA256(new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                throw new NotImplementedException("The method getPublicKeyById is not implemented");
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return rsaPrivateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return privateKeyId;
            }
        });
        return algorithm;
    }
}

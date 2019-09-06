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

package com.tmobile.oss.security.taap.poptoken.builder.testutils;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;

import org.apache.commons.codec.binary.Base64;

public class PopTokenBuilderTestUtils {

    public static KeyPair createNewRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static RSAPrivateKey createNewRsaPrivateKey() throws NoSuchAlgorithmException {
        return (RSAPrivateKey) createNewRsaKeyPair().getPrivate();
    }

    public static String generatePrivateKeyPemString(byte[] keyBytes) throws IOException {
        StringBuilder privateKeyPemStringBuilder = new StringBuilder();
        privateKeyPemStringBuilder.append("-----BEGIN PRIVATE KEY-----");
        privateKeyPemStringBuilder.append(Base64.encodeBase64String(keyBytes));
        privateKeyPemStringBuilder.append("-----END PRIVATE KEY-----");
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
}

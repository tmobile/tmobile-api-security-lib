package com.tmobile.oss.security.taap.poptoken.builder.testutils;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.UUID;

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

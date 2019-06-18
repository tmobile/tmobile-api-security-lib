package com.tmobile.security.taap.poptoken.validator.testhelper;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedHashMap;

import org.apache.commons.codec.binary.Base64;

import com.tmobile.security.taap.poptoken.builder.ExtPopTokenBuilder;
import com.tmobile.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.security.taap.poptoken.builder.exception.PopTokenBuilderException;

public class PopTokenValidatorTestHelper {

    public static String createPopToken(LinkedHashMap<String, String> ehtsKeyValueMap, Date tokenIssuedAtDate,
            int tokenValidForSeconds, RSAPrivateKey rsaPrivateKey) throws PopTokenBuilderException {

        PopTokenBuilder popTokenBuilder = new ExtPopTokenBuilder(tokenIssuedAtDate, tokenValidForSeconds);

        return popTokenBuilder.setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(rsaPrivateKey) //
                .build();
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
}

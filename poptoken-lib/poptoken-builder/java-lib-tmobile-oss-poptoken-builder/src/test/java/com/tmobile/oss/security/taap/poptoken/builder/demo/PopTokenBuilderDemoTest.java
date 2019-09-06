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

public class PopTokenBuilderDemoTest {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenBuilderDemoTest.class);

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Test
    public void buildPopTokenWithPrivateKeyPemString() throws PopTokenBuilderException {

        String privateKeyPemString = "-----BEGIN PRIVATE KEY-----" + LINE_SEPARATOR //
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCr9gryaGU6iPEw" + LINE_SEPARATOR //
                + "/27c5v6VgFliRvBOfmwTWW61XjGQL5Jaj7KKqCKWJIXyniEQQ1bbaMlJ+ymIiobv" + LINE_SEPARATOR //
                + "Mo4QQUh9+NBYHJJfz86NFbTC3VgLXCetHy4REqobGFO8Bb2DEqIlMhhlNSLtEmGx" + LINE_SEPARATOR //
                + "NhHHMCen6nJ7AQa9W5vr8S7uffHmfQF7X/5BtvqP40k8038BDnaeB71I5HubrC0d" + LINE_SEPARATOR //
                + "jom0/kgzytEZfEZUE32mBFJpjl2ZWBJoMd61tfarCzUEFHcMyMQDQnhSq6jwFdIx" + LINE_SEPARATOR //
                + "tl8Dy+fq+hmzdj58mRZoM2aQb3KYNajKe9JKeJKwWwwOwQzAxmC08qkR5wTAA8vT" + LINE_SEPARATOR //
                + "rjJ2hryDAgMBAAECggEAeKi2u6q2xODL5CaHAqduoTYjActm2JzqdpU9EjPasSJA" + LINE_SEPARATOR //
                + "Hh1QGOyrABD2j+uWpZOqgV/ARZHfbbhNv88IUa2NER8iCYFaz7G/a818PXMUUTxD" + LINE_SEPARATOR //
                + "dr03FLG0/DgQoRCiDjNn5JOG/JTRQemw9KhMxygp2y+tTlPFB98cw+xCkwN6Vc/g" + LINE_SEPARATOR //
                + "ZNhhvvrIIp7tj78fQUD2m8QdCIZ6M2nE84Rqxcpp4iLZsZSHtmuVzCb769bfs804" + LINE_SEPARATOR //
                + "U0Q6xveNIDQi6/GPpBtiZU2zekkc/CNQ1yIGwk1//MN3ae5R8Y62+BVrpwO2FjNP" + LINE_SEPARATOR //
                + "ZQQfa8ZgPT4y9DauYSp5wf4SWAPsR9Z+Jy8kHfz6eQKBgQDS7G9o5FmqWLhNYCwg" + LINE_SEPARATOR //
                + "ddIRDXGoQOoVfw9uufX43K/QlCyXdttO8ZZq+jxfaW3jm2hx5OrpVVIGQnCXA1yO" + LINE_SEPARATOR //
                + "sZMHbAsDMH1AXEttSTsnR7jEkMFrD6oakNYZxIptj4NVe7TZ4+DxCNvEugUKedpc" + LINE_SEPARATOR //
                + "Z5BCyaivmo+Uab8Yode5yB62NQKBgQDQtfuNg1+OZDXdyma4J4HDQmvNOVlrI7Aq" + LINE_SEPARATOR //
                + "QRhSb/ZrwGSGFyr0avLkdHlKzgIMt+zrtDmaWrzu4+JrivNggutelPpntiN6mhoY" + LINE_SEPARATOR //
                + "9c3Q/kVZ4reK8RpL7SN9C0WAnTWMQfS4vgByrzkTnnxZzkE2CTsLS3Xc84vP0vXD" + LINE_SEPARATOR //
                + "282frAue1wKBgQCQSJqBl0tbAuu4SmSFI/O6JIcuQJGgeNV2uhDv1w8R0HqcdfrZ" + LINE_SEPARATOR //
                + "ituJfHoWDonUW/fbiWvEh8/fZk2cj/kdx407U4ZI/T+A6mHSdXjYivByzk7xTLrh" + LINE_SEPARATOR //
                + "B1jeMZs8DSMbM89oCcFTQOsNLO7L1sUv1sxRU59n2IQFUz0cvYFTnficTQKBgByf" + LINE_SEPARATOR //
                + "mKxDxCsnGywbwhKneGhrB5XRs62560MgQlGsAUOt0xuAuedjc4RZZPkZX7aW0utQ" + LINE_SEPARATOR //
                + "gEXnA9pPbpIJMG+gBN+n1t+6XwtFbybVLzDmbmRxb3KitlSLZT6U+Sc2aE2gDgv4" + LINE_SEPARATOR //
                + "It+XoGBMcAlw/AiJI4vdAYEX9ai+6e2+i2jGk6FpAoGAVqTL33m5GiA5r2ZjMPNt" + LINE_SEPARATOR //
                + "MnmvcP9otFVVJjOyQvEzkWIui9yCpM0n0UhNO20CxuqLkflUOdMjVmVAAeFVgeLe" + LINE_SEPARATOR //
                + "KRIa4zrqAnhs++vg4g+9Jme5c1nQMQZYHnNYj+KvNZEdriDofBm7DKroVWd0fEn1" + LINE_SEPARATOR //
                + "307np4UkLYIbZhCArTpVAV4=" + LINE_SEPARATOR //
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
        logger.info("popToken: " + popToken);
        assertTrue(StringUtils.isNotBlank(popToken));
    }
}

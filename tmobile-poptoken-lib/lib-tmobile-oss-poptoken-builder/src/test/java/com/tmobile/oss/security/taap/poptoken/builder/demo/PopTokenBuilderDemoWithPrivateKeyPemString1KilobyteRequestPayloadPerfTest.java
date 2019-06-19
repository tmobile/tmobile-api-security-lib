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
import com.tmobile.oss.security.taap.poptoken.builder.testutils.PopTokenBuilderTestUtils;

public class PopTokenBuilderDemoWithPrivateKeyPemString1KilobyteRequestPayloadPerfTest {

    private static final Logger logger = LoggerFactory
            .getLogger(PopTokenBuilderDemoWithPrivateKeyPemString1KilobyteRequestPayloadPerfTest.class);

    private static final int NUM_BYTES_IN_ONE_KILOBYTE = 1 * 1024;
    private static final String ONE_KILOBYTE_REQUEST_PAYLOAD = PopTokenBuilderTestUtils
            .createRequestPayload(NUM_BYTES_IN_ONE_KILOBYTE);
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

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < 1000; i++) {
            buildPopTokenWithPrivateKeyPemString(privateKeyPemString);
        }

        long actualProcessingTime = System.currentTimeMillis() - startTime;
        long expectedProcessingTime = 20000L;

        logger.info("PopTokenBuilderDemoWithPrivateKeyPemString1KilobytePayloadPerfTest -> actualProcessingTime: "
                + actualProcessingTime + " ms"); //
        assertTrue("Should not have taken more than " + expectedProcessingTime + " millis for 1000 validations, actualProcessingTime: "
                + actualProcessingTime, (actualProcessingTime <= expectedProcessingTime)); //
    }

    // ===== helper methods ===== //

    private void buildPopTokenWithPrivateKeyPemString(String privateKeyPemString) throws PopTokenBuilderException {
        // STEP 1: Build the LinkedHashMap of ehts (external headers to sign) key and values
        LinkedHashMap<String, String> ehtsKeyValueMap = new LinkedHashMap<>();
        ehtsKeyValueMap.put("Content-Type", "application/json");
        ehtsKeyValueMap.put("Authorization", "Bearer UtKV75JJbVAewOrkHMXhLbiQ11SS");
        ehtsKeyValueMap.put(PopEhtsKey.URI.keyName(), "/commerce/v1/orders"); // URL = https://api.t-mobile.com/commerce/v1/orders
        ehtsKeyValueMap.put(PopEhtsKey.HTTP_METHOD.keyName(), "post");
        ehtsKeyValueMap.put(PopEhtsKey.BODY.keyName(), ONE_KILOBYTE_REQUEST_PAYLOAD);

        // STEP 2: Generate PoP token using PoPTokenBuilder
        String popToken = PopTokenBuilder.newInstance() //
                .setEhtsKeyValueMap(ehtsKeyValueMap) //
                .signWith(privateKeyPemString) //
                .build();

        // verify the popToken has text
        assertTrue(StringUtils.isNotBlank(popToken));
    }
}

package com.tmobile.oss.security.taap.poptoken.builder.demo;

import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import com.tmobile.oss.security.taap.poptoken.builder.PopEhtsKey;
import com.tmobile.oss.security.taap.poptoken.builder.PopTokenBuilder;
import com.tmobile.oss.security.taap.poptoken.builder.exception.PopTokenBuilderException;

public class PopTokenBuilderDemoWithEncryptedPrivateKeyPemStringAndPasswordNoRequestPayloadPerfTest {

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
        String aes256EncryptedPrivateKeyPemString = "-----BEGIN ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR //
                + "MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIJlzllfZVQ3wCAggA" + LINE_SEPARATOR //
                + "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDzuFTXD+z30fBqq1RVRLewBIIE" + LINE_SEPARATOR //
                + "0M0sPeGOsQkswb8u8oEHc3jqTuPCoHKnYeOuosVuWKm9USX3OBftXcxwIgrC322W" + LINE_SEPARATOR //
                + "UoqsfMUgX1MMqIWfvBYzHm7eDEX49G2iJJ4tjm58jEtTAU1JNKjij3taXMFs4dvn" + LINE_SEPARATOR //
                + "x0XMKAzOrae94RG0GExzsQG8Qwq59zigvs6PxcPTaHhuNkioSX+IhJ+yGvJ7eMxy" + LINE_SEPARATOR //
                + "zzXClQgdEBnhfx854R0pkeJ+m/Z51q9sHvrJ1KedNXkBUnv1URZrUiN4dJyXXMe+" + LINE_SEPARATOR //
                + "2ewMHda3xBFyfjNO5Q+yapUxpK2XRMn0nSgXkWJYiANzbAw9F3cyQWD86zKAn72t" + LINE_SEPARATOR //
                + "0dAZ8vlns2d2mE2FFNpYDg8zd4WR9CVSFTEj1k1ExTWdU7iH0DSupHaKdKFnHSsY" + LINE_SEPARATOR //
                + "mVRr5rfWGAJA2n7XeF5KeWAxh7ksgoLL7UJYPTN2dAuMeAezt82jAKD650JE+wKX" + LINE_SEPARATOR //
                + "i+6iDpD2pEsDjZNE4oV9l2hRy43p+nxQuQYAbmjAZJedjGz3sAaKAyteL9jGjyPb" + LINE_SEPARATOR //
                + "EA3AKq2V5CmrY1QicR7EwfUEyOn8m4j++HXie9kIAyTd5myKbSVCDKqtAsS0rCoo" + LINE_SEPARATOR //
                + "JZEyboRsKhwkpVGC0i795e/tOODIiKOumPe8pO2KN5kFgqLvwKAceyR6d9OY/zWr" + LINE_SEPARATOR //
                + "0Gv5JNk50FOpTqxgW70WYOA2aZZn/QvaJYbMuhNyH/r+GuW4JO3pDHgNR/p+t3db" + LINE_SEPARATOR //
                + "7pS8bpAJSby0IvBsrtq1fxmLiaKRkyeoKISW/WAUJtjU+HvFVvEomCZpJ/MCDccs" + LINE_SEPARATOR //
                + "hIffFXxZ4C8r5dqS+q9RiM5XHWgEdgY4AJ+6uNkzXZ/Q0UIpDrw38xI3Vf7ChdtC" + LINE_SEPARATOR //
                + "lEFYdzZugECWRVpW9IG9flOY7dncGnuP8ncjfTy1W8RI0JdQcoNmz1HJ7u7zbyAj" + LINE_SEPARATOR //
                + "ux9orkNNTp6R5tmcBKwmdgLbdB7IZAO/VUNmvVCK4WIpQ/DSAsPt5qvcG30L+2DI" + LINE_SEPARATOR //
                + "+cMKPxHftNFG0dAI8z0eSqIvkuRmjnZ/ctwzjDJIjLoJFKW8ehebM6TVvquQW1aF" + LINE_SEPARATOR //
                + "Jaw/hXVm+tZGJOIA5ZMeqAZgeYckieII7yufZclr27abWL7mVJw9WvzPNjkCQ8YZ" + LINE_SEPARATOR //
                + "AubTPpg3NRT/VGQnt3JLcX+Wx7cUIaRSHRyivdwnQxokKg8igL5m+vzuBgB1PHQD" + LINE_SEPARATOR //
                + "TuU8i83fju0/QK5iq4f/G4C3eXUKWBcvCY3v7Up35SoGwMGf9uEH/4vCfvgauGlz" + LINE_SEPARATOR //
                + "Z7azUj9zydvjOFYXhaVXzeOFGUL/a3la2e7evoSKhD9S7ICBo8uHreWxSLRf7Ayd" + LINE_SEPARATOR //
                + "azbfjpXQ7eglvx02Bkzng+ipW3WD+jjMed8UmkAIpNJKPhPlpMJeA42ArDMPohPi" + LINE_SEPARATOR //
                + "jLauXbHzS/I306CtwR2vFchIwJECVwkSeQmuxd6g4KUbIdpc2kvZvweHwa1xS8OQ" + LINE_SEPARATOR //
                + "hljw7FBC8r6z7tbY/ZXvBY302AbfxxQUrQA/0E1aWzx4b5oPe3d+DeKKVNr/Zeog" + LINE_SEPARATOR //
                + "klJJF40/Muk/ouGaPtsCl/UbChOmmWbMj65hDGx2hGshdFnYV0KiguUzUg76SQg3" + LINE_SEPARATOR //
                + "c+neqDC3SxdStuxDnUwJDC4zcV7dL3XpmPWDYnBitNQF9wbv7+Knhkd/WrHyvhC0" + LINE_SEPARATOR //
                + "D8xd6YGA9D/7zwrDNX/rO5xbSxcINLLVfkK2VeR8Pr60" + LINE_SEPARATOR //
                + "-----END ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR; //
        String privateKeyPassword = "foobar";

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < 1000; i++) {
            buildPopTokenWithEncryptedPrivateKeyPemString(aes256EncryptedPrivateKeyPemString, privateKeyPassword);
        }

        long endTime = System.currentTimeMillis();
        assertTrue("Actual processing time is " + (endTime - startTime) + " ms", (endTime - startTime) <= 35000);
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
        String des3EncryptedPrivateKeyPemString = "-----BEGIN ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR //
                + "MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIqkcj3GwIG+sCAggA" + LINE_SEPARATOR //
                + "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBB2dKw1TCmjIttnZj2A6QDXBIIE" + LINE_SEPARATOR //
                + "0CqJUGKJ6r7bm0yr8rJROCnTjpnyUsoM3L6DyjFHamXBEMxcErPbYJu9F+7ws1T/" + LINE_SEPARATOR //
                + "qBl38YPlO/OKcamxy27hUnlsY+ysbrOvGnv7e2RXPZfmSNLbqfYE05Kv4ig0SQ8O" + LINE_SEPARATOR //
                + "UmOdA8dD9uQFSG/py1hMXdeHucO0JM4UhVWR0HdYbyc6t5Y6RqmHNH1b1riCbM3X" + LINE_SEPARATOR //
                + "UGfhmYPzYH6y+SAhTTQtnp+Ug+vmJFmf8saCjdqN43skzAvmx0Go9ZNub1vYZCz0" + LINE_SEPARATOR //
                + "aAdjNCJFl9lyhHkiwoOUPJiSN+NyM/0RhJGyYVwSq/viXf7AOO2a0JJpIxse6yy/" + LINE_SEPARATOR //
                + "3uKSUog3xcLwEvWRzxUbvP6hQD5r0FVK9Jr0vNWeqcQrCt99Gx6gNudDiBFDDTd5" + LINE_SEPARATOR //
                + "5NlJCoYl3CEgvynGR9/D5EQe0XhpFsIfx3qCxpniGI7J8gqkI3GMrmk5YZ8lk6Hi" + LINE_SEPARATOR //
                + "hBcbuQx2JFrr1tWp2HwU3+9fJ2ch5do7KGsn0u/Wx022YqnDWZ/HfpLJZKJvD6Qg" + LINE_SEPARATOR //
                + "Z0wO8uzPTi7t7qiF7/FcsC0qB4Ky467iAXx9HytczZPoWdi7A1PiGOQ0bd/WbE90" + LINE_SEPARATOR //
                + "Bw2anKnlHewqMEJqR10iSUB+0/hz2focWmmpzmWncaOTWKhLZRkGpDnq9RvUlyMp" + LINE_SEPARATOR //
                + "EceVWQdq1gNfLk1N0Vo2ZsjWLqy3q3L/hfbmFzs1rXPj1Dwsj7doiYwFmmG3+qjG" + LINE_SEPARATOR //
                + "wMVh1Ofs2d8ixZEgbuhGDvgcYBN1OkuyfUE0FCSbh/BaDy2jsnNbzNbDEj8shcvf" + LINE_SEPARATOR //
                + "KdM8g+1NsIeuJGD8ZsZc8zLU4xzS2v55x3O/X1QlraoFBUPuC3iLMksH/ViWRCU5" + LINE_SEPARATOR //
                + "zUkTKc0sRsdtYtkvG611XtauZkubIAkV0Nj5ApwZw1Wes9odFoCxV9OWViUNmbCy" + LINE_SEPARATOR //
                + "6UJNgBMnJPywl4uChNZhOgv2YPBUHITHWCD3EvNizRjwulx3F+oX57S5yONQMfFN" + LINE_SEPARATOR //
                + "4wBX8gMXIqEkWTNdXJcVKknACxd/bPZ55rfuDGzKpqw1lkjCK7Ytn7qeZBHBifGz" + LINE_SEPARATOR //
                + "O+B/E7PDXc/KQN5TLI1O10bbuBKCAXwi8U5r5/4EXjd14ICzgSuBOVR4nKoSJU2m" + LINE_SEPARATOR //
                + "L7q5DdH3I1KZwAajvgMXMqk13aGlTpYe1IKJbGBz5K9LkIM6QlUTAKFvAZ+c7q/r" + LINE_SEPARATOR //
                + "4tSrevQIZ6awby5JeIgsh8ux6IBalVw4zUVj6yuLxxIgvohT/8YhK2W9hMGdrDVD" + LINE_SEPARATOR //
                + "W3lqZf/ca3mGM6b9Zxi5N10lxwpezLWRnmdxl92AgY19TH1DnPCCbSREIgp9TUf5" + LINE_SEPARATOR //
                + "yn67ZhquJBwJER08OS4JXTc0SQuFfV2s+v4CbIdxlbzauTjAVgbZMDnzzt4dGDtx" + LINE_SEPARATOR //
                + "/W4Pqmvks/9XIdQlVcCgqrpTShL/GK1RmGFNq9wfkKMK07kwyArFYcqmP0v375PQ" + LINE_SEPARATOR //
                + "Q9ImztFcMvDolnC8zZ/UMCYpEI+HKomSO+fLpyYQHeptRgR+emOd7myUTdmTjPZX" + LINE_SEPARATOR //
                + "DHjihsfyKlI0eeGUk43ckpEBgp9p+kAAEHhXsLnEbifnlAgTqBO0UE8dTzu236F6" + LINE_SEPARATOR //
                + "87fLisqeCXx/TjpwiUeDf/uDm6p1TMi13i2JCz05DdJxejivq8u6BbdRTTGsC091" + LINE_SEPARATOR //
                + "XbgqtwlMzHKMV1jUn6bBbk4f9foosUBCtxq9ESQBvA3C" + LINE_SEPARATOR //
                + "-----END ENCRYPTED PRIVATE KEY-----" + LINE_SEPARATOR; //
        String privateKeyPassword = "foobar";

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < 1000; i++) {
            buildPopTokenWithEncryptedPrivateKeyPemString(des3EncryptedPrivateKeyPemString, privateKeyPassword);
        }
        long endTime = System.currentTimeMillis();
        assertTrue("Actual processing time is " + (endTime - startTime) + " ms", (endTime - startTime) <= 35000);
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

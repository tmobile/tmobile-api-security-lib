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

package com.tmobile.oss.security.taap.poptoken.validator.utils;

import static org.junit.Assert.assertNotNull;

import java.security.PublicKey;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tmobile.oss.security.taap.poptoken.validator.utils.PopTokenValidatorUtils;

public class PopTokenValidatorUtilsTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorUtilsTest.class);

    @Test
    public void keyPemStringToRsaPublicKey__withX509KeyPemString__successfullyGeneratesPublicKey() throws Exception {

        // setup the data
        String pkcs8PublicKeyPemString = "-----BEGIN PUBLIC KEY-----\r\n" + //
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcN6NPvcBXSDa0WxmFQj\r\n" + //
                "LJZQaYBcw60vBIn7KOmK++qTz6GPtci1AOzv67uxlG5urWFSSCiaNqGu8jN0HheF\r\n" + //
                "PPmz35HLgqj+UuNxXKXy82RBCOrPrhOODoP6YD4Bj065NXUPEl0KHEBDrgEulhfl\r\n" + //
                "MxhuxiaXcJb0dlDTO5Lp2e8KwgCmLu8iJuHzoOLomz/FjF0tx0qdjbNAqw7uRqyd\r\n" + //
                "2Hz/e1RIhddiy45H0oElcFemPLfWlgSxKNFsZK0yEws/gtwhcjztXfEPbVmq0Les\r\n" + //
                "wZ8A+tAEPVk+vFHqHfxy9XHhkF4RN4f7+/6qU/Ou+ObVPDEAgJPDa+clDTqrjKGo\r\n" + //
                "fwIDAQAB\r\n" + //
                "-----END PUBLIC KEY-----\r\n"; //

        // perform an action
        PublicKey publicKey = PopTokenValidatorUtils.keyPemStringToRsaPublicKey(pkcs8PublicKeyPemString);

        // validate the result
        assertNotNull("Public key should not be null", publicKey);
    }

    @Test
    public void keyPemStringToRsaPublicKey__withX509KeyPemStringWithoutLineSeparators__successfullyGeneratesPublicKey()
            throws Exception {

        // setup the data
        String publicKeyStringWithoutLineSeparators = "-----BEGIN PUBLIC KEY-----" + //
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcN6NPvcBXSDa0WxmFQj" + //
                "LJZQaYBcw60vBIn7KOmK++qTz6GPtci1AOzv67uxlG5urWFSSCiaNqGu8jN0HheF" + //
                "PPmz35HLgqj+UuNxXKXy82RBCOrPrhOODoP6YD4Bj065NXUPEl0KHEBDrgEulhfl" + //
                "MxhuxiaXcJb0dlDTO5Lp2e8KwgCmLu8iJuHzoOLomz/FjF0tx0qdjbNAqw7uRqyd" + //
                "2Hz/e1RIhddiy45H0oElcFemPLfWlgSxKNFsZK0yEws/gtwhcjztXfEPbVmq0Les" + //
                "wZ8A+tAEPVk+vFHqHfxy9XHhkF4RN4f7+/6qU/Ou+ObVPDEAgJPDa+clDTqrjKGo" + //
                "fwIDAQAB" + //
                "-----END PUBLIC KEY-----"; //

        // perform an action
        PublicKey publicKey = PopTokenValidatorUtils.keyPemStringToRsaPublicKey(publicKeyStringWithoutLineSeparators);

        // validate the result
        assertNotNull("Public key should not be null", publicKey);
    }

    @Test
    public void keyPemStringToRsaPublicKey__withPkcs1KeyPemString__successfullyGeneratesPublicKey() throws Exception {

        // setup the data
        String pkcs1PublicKeyPemString = "-----BEGIN RSA PUBLIC KEY-----\r\n" + //
                "MIIBCgKCAQEAvcN6NPvcBXSDa0WxmFQj\r\n" + //
                "LJZQaYBcw60vBIn7KOmK++qTz6GPtci1AOzv67uxlG5urWFSSCiaNqGu8jN0HheF\r\n" + //
                "PPmz35HLgqj+UuNxXKXy82RBCOrPrhOODoP6YD4Bj065NXUPEl0KHEBDrgEulhfl\r\n" + //
                "MxhuxiaXcJb0dlDTO5Lp2e8KwgCmLu8iJuHzoOLomz/FjF0tx0qdjbNAqw7uRqyd\r\n" + //
                "2Hz/e1RIhddiy45H0oElcFemPLfWlgSxKNFsZK0yEws/gtwhcjztXfEPbVmq0Les\r\n" + //
                "wZ8A+tAEPVk+vFHqHfxy9XHhkF4RN4f7+/6qU/Ou+ObVPDEAgJPDa+clDTqrjKGo\r\n" + //
                "fwIDAQAB\r\n" + //
                "-----END RSA PUBLIC KEY-----\r\n"; //

        // perform an action
        PublicKey publicKey = PopTokenValidatorUtils.keyPemStringToRsaPublicKey(pkcs1PublicKeyPemString);

        // validate the result
        assertNotNull("Public key should not be null", publicKey);
    }

    @Test
    public void keyPemStringToRsaPublicKey__withPkcs1KeyPemStringWithoutLineSeparators__successfullyGeneratesPublicKey()
            throws Exception {

        // setup the data
        String publicKeyStringWithoutNewLineChars = "-----BEGIN RSA PUBLIC KEY-----" + //
                "MIIBCgKCAQEAvcN6NPvcBXSDa0WxmFQj" + //
                "LJZQaYBcw60vBIn7KOmK++qTz6GPtci1AOzv67uxlG5urWFSSCiaNqGu8jN0HheF" + //
                "PPmz35HLgqj+UuNxXKXy82RBCOrPrhOODoP6YD4Bj065NXUPEl0KHEBDrgEulhfl" + //
                "MxhuxiaXcJb0dlDTO5Lp2e8KwgCmLu8iJuHzoOLomz/FjF0tx0qdjbNAqw7uRqyd" + //
                "2Hz/e1RIhddiy45H0oElcFemPLfWlgSxKNFsZK0yEws/gtwhcjztXfEPbVmq0Les" + //
                "wZ8A+tAEPVk+vFHqHfxy9XHhkF4RN4f7+/6qU/Ou+ObVPDEAgJPDa+clDTqrjKGo" + //
                "fwIDAQAB" + //
                "-----END RSA PUBLIC KEY-----"; //

        // perform an action
        PublicKey publicKey = PopTokenValidatorUtils.keyPemStringToRsaPublicKey(publicKeyStringWithoutNewLineChars);

        // validate the result
        assertNotNull("Public key should not be null", publicKey);
    }
}

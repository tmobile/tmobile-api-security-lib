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

package com.tmobile.oss.security.taap.poptoken.validator;

/**
 * Represents the PoP ehts key.
 */
public enum PopEhtsKey {

    /**
     * Represents the "uri" ehts key name.
     */
    URI("uri"), //

    /**
     * Represents the "body" ehts key name.
     */
    BODY("body"), //

    /**
     * Represents the "http-method" ehts key name.
     */
    HTTP_METHOD("http-method"); //

    private String keyName;

    /**
     * Constructs the EhtsKey enum using the specified key name
     * 
     * @param keyName The ehts key name.
     */
    private PopEhtsKey(String keyName) {
        this.keyName = keyName;
    }

    /**
     * Returns the ehts key name.
     * 
     * @return The ehts key name
     */
    public String keyName() {
        return this.keyName;
    }
}

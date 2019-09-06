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

package com.tmobile.oss.security.taap.poptoken.validator.exception;

/**
 * This exception is thrown when the PoP token being validated has expired.
 */
public class PopTokenExpiredException extends PopTokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopTokenExpiredException using the specified message.
     * 
     * @param message The exception message
     */
    public PopTokenExpiredException(String message) {
        super(message);
    }

    /**
     * Constructs the PopTokenExpiredException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public PopTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}

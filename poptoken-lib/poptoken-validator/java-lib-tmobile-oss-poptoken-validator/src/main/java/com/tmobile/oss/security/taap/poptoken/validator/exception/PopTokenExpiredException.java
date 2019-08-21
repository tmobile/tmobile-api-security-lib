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

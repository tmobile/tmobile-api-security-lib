package com.tmobile.security.taap.poptoken.validator.exception;

/**
 * This exception is thrown when the PoP token contains the invalid edts (external data to sign) hash value.
 */
public class PopTokenInvalidEdtsHashException extends PopTokenValidatorException {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopTokenInvalidEdtsException using the specified message.
     * 
     * @param message The exception message
     */
    public PopTokenInvalidEdtsHashException(String message) {
        super(message);
    }

    /**
     * Constructs the PopTokenInvalidEdtsException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public PopTokenInvalidEdtsHashException(String message, Throwable cause) {
        super(message, cause);
    }
}

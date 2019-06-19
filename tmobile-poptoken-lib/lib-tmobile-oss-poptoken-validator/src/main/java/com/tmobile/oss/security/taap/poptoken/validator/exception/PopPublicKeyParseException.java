package com.tmobile.oss.security.taap.poptoken.validator.exception;

/**
 * This exception is thrown when there is an error while parsing the PoP public key.
 */
public class PopPublicKeyParseException extends PopTokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopPublicKeyParseException using the specified message.
     * 
     * @param message The exception message
     */
    public PopPublicKeyParseException(String message) {
        super(message);
    }

    /**
     * Constructs the PopPublicKeyParseException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public PopPublicKeyParseException(String message, Throwable cause) {
        super(message, cause);
    }
}

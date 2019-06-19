package com.tmobile.oss.security.taap.poptoken.validator.exception;

/**
 * This exception is thrown when the PoP token is invalid.
 */
public class InvalidPopTokenException extends PopTokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs the InvalidPopTokenException using the specified message.
     * 
     * @param message The exception message
     */
    public InvalidPopTokenException(String message) {
        super(message);
    }

    /**
     * Constructs the InvalidPopTokenException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public InvalidPopTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}

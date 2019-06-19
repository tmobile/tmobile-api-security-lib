package com.tmobile.oss.security.taap.poptoken.validator.exception;

/**
 * This exception is thrown when there is an error while validating the PoP token.
 * <p>
 * It is also a base class for all the PoP validator related custom exceptions.
 */
public class PopTokenValidatorException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopTokenValidatorException using the specified message.
     * 
     * @param message The exception message
     */
    public PopTokenValidatorException(String message) {
        super(message);
    }

    /**
     * Constructs the PopTokenValidatorException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public PopTokenValidatorException(String message, Throwable cause) {
        super(message, cause);
    }
}

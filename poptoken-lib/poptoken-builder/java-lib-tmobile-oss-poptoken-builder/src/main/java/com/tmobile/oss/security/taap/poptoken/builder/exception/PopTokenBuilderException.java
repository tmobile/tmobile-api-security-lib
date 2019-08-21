package com.tmobile.oss.security.taap.poptoken.builder.exception;

/**
 * This exception is thrown when there is an error while building the PoP token.
 * <p>
 * This is also a base class for all the PoP builder related custom exceptions.
 */
public class PopTokenBuilderException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopTokenBuilderException using the specified message.
     * 
     * @param message The exception message
     */
    public PopTokenBuilderException(String message) {
        super(message);
    }

    /**
     * Constructs the PopTokenBuilderException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public PopTokenBuilderException(String message, Throwable cause) {
        super(message, cause);
    }
}

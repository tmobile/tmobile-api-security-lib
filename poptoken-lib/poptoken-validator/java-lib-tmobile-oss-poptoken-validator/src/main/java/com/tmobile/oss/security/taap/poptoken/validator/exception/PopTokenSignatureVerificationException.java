package com.tmobile.oss.security.taap.poptoken.validator.exception;

/**
 * This exception is thrown when the PoP token being validated has expired.
 */
public class PopTokenSignatureVerificationException extends PopTokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopTokenSignatureVerificationException using the specified message.
     * 
     * @param message The exception message
     */
    public PopTokenSignatureVerificationException(String message) {
        super(message);
    }

    /**
     * Constructs the PopTokenSignatureVerificationException using the specified message and cause.
     * 
     * @param message The exception message
     * @param cause The cause
     */
    public PopTokenSignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}

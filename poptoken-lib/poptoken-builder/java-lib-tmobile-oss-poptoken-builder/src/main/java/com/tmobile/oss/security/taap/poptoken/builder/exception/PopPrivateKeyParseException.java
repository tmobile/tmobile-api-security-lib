package com.tmobile.oss.security.taap.poptoken.builder.exception;

/**
 * This exception is thrown when the PoP private key cannot be parsed.
 */
public class PopPrivateKeyParseException extends PopTokenBuilderException {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs the PopPrivateKeyParseException using the specified message.
     * @param message The exception message
     */
    public PopPrivateKeyParseException(String message) {
        super(message);
    }

    /**
     * Constructs the PopPrivateKeyParseException using the specified message and cause.
     * @param message The exception message
     * @param cause The cause
     */
    public PopPrivateKeyParseException(String message, Throwable cause) {
        super(message, cause);
    }
}

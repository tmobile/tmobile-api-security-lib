package com.tmobile.security.taap.poptoken.validator;

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

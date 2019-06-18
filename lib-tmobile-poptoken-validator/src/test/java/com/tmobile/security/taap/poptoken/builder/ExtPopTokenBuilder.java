package com.tmobile.security.taap.poptoken.builder;

import java.util.Date;

public class ExtPopTokenBuilder extends PopTokenBuilder {

    private Date tokenIssuedAtDate;
    private int tokenValidForSeconds;

    public ExtPopTokenBuilder(Date tokenIssuedAtDate, int tokenValidForSeconds) {
        this.tokenIssuedAtDate = tokenIssuedAtDate;
        this.tokenValidForSeconds = tokenValidForSeconds;
    }

    @Override
    Date getIssuedAt() {
        return tokenIssuedAtDate;
    }

    @Override
    protected Date getExpiration(Date issuedAt) {
        return new Date(issuedAt.getTime() + tokenValidForSeconds * 1000);
    }
}

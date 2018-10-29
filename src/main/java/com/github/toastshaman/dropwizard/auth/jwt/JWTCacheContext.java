package com.github.toastshaman.dropwizard.auth.jwt;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class JWTCacheContext {

    private final String jwt;
    private final JWTClaimsSet claims;

    public JWTCacheContext(String jwt, JWTClaimsSet claims) {
        this.jwt = requireNonNull(jwt);
        this.claims = requireNonNull(claims);
    }

    public String getJwt() {
        return jwt;
    }

    public JWTClaimsSet getClaims() {
        return claims;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWTCacheContext that = (JWTCacheContext) o;
        return Objects.equals(jwt, that.jwt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jwt);
    }
}

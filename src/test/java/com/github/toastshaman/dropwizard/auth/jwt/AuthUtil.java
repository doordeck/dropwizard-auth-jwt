package com.github.toastshaman.dropwizard.auth.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.Authorizer;
import io.dropwizard.auth.PrincipalImpl;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

public class AuthUtil {

    public static Authenticator<JWTClaimsSet, Principal> getJWTAuthenticator(final List<String> validUsers) {
        return context -> {
            final String subject = context.getSubject();

            if (validUsers.contains(subject)) {
                return Optional.of(new PrincipalImpl(subject));
            }

            if ("bad-guy".equals(subject)) {
                throw new AuthenticationException("CRAP");
            }

            return Optional.empty();
        };
    }

    public static Authorizer<Principal> getTestAuthorizer(final String validUser, final String validRole) {
        return (principal, role) -> principal != null && validUser.equals(principal.getName()) && validRole.equals(role);
    }
}
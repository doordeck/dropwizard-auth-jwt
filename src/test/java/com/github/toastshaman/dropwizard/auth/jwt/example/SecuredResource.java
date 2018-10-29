package com.github.toastshaman.dropwizard.auth.jwt.example;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import io.dropwizard.auth.Auth;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import java.security.Principal;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static java.util.Collections.singletonMap;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/jwt")
@Produces(APPLICATION_JSON)
public class SecuredResource {

    private final JWSSigner signer;

    public SecuredResource(byte[] tokenSecret) throws KeyLengthException {
        this.signer = new MACSigner(tokenSecret);
    }

    @GET
    @Path("/generate-expired-token")
    public Map<String, String> generateExpiredToken() {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.now().minus(30, ChronoUnit.MINUTES)))
                .subject("good-guy")
                .build();

        try {
            // Prepare JWS object with "Hello, world!" payload
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(claims.toJSONObject()));

            // Apply the HMAC
            jwsObject.sign(signer);

            return singletonMap("token", jwsObject.serialize());
        }
        catch (JOSEException e) { throw Throwables.propagate(e); }
    }

    @GET
    @Path("/generate-valid-token")
    public Map<String, String> generateValidToken() {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES)))
                .subject("good-guy")
                .build();

        try {
            // Prepare JWS object with "Hello, world!" payload
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(claims.toJSONObject()));

            // Apply the HMAC
            jwsObject.sign(signer);

            return singletonMap("token", jwsObject.serialize());
        }
        catch (JOSEException e) { throw Throwables.propagate(e); }
    }

    @GET
    @Path("/check-token")
    public Map<String, Object> get(@Auth Principal user) {
        return ImmutableMap.<String, Object>of("username", user.getName(), "id", ((MyUser) user).getId());
    }
}

package com.github.toastshaman.dropwizard.auth.jwt;

import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.dropwizard.jersey.DropwizardResourceConfig;
import org.junit.Test;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestFilter;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.HttpHeaders.WWW_AUTHENTICATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;

public class JwtAuthProviderTest extends AuthBaseTest<JwtAuthProviderTest.JwtAuthTestResourceConfig> {

    private static final byte[] SECRET = Base64.getDecoder().decode("vZMLblzWrdFRLAClXetwIjL8mPccjdjxjQidkJFGybYGkdJhu4GmzUsfmMcwsAokXE7a0y1ryhsVndXrKYQ50g==");

    static class JwtAuthTestResourceConfig extends AuthBaseResourceConfig {
        protected ContainerRequestFilter getAuthFilter() {

            final ConfigurableJWTProcessor<SecurityContext> consumer = new DefaultJWTProcessor<>();

            JWKSource<SecurityContext> keySource = new ImmutableSecret<>(SECRET);
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, keySource);
            consumer.setJWSKeySelector(keySelector);


//            final JwtConsumer consumer = new JwtConsumerBuilder()
//                .setRequireExpirationTime() // the JWT must have an expiration time
//                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
//                .setRequireSubject() // the JWT must have a subject claim
//                .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
//                .setExpectedAudience("Audience") // whom the JWT needs to have been issued by
//                .setVerificationKey(new HmacKey(SECRET_KEY.getBytes(UTF_8))) // verify the signature with the public key
//                .setRelaxVerificationKeyValidation() // relaxes key length requirement
//                .build();// create the JwtConsumer instance

            return new JwtAuthFilter.Builder<>()
                .setCookieName(COOKIE_NAME)
                .setJwtConsumer(consumer)
                .setPrefix(BEARER_PREFIX)
                .setAuthorizer(AuthUtil.getTestAuthorizer(ADMIN_USER, ADMIN_ROLE))
                .setAuthenticator(AuthUtil.getJWTAuthenticator(ImmutableList.of(ADMIN_USER, ORDINARY_USER)))
                .buildAuthFilter();
        }
    }

    @Test
    public void respondsToInvalidSignaturesWith401() throws Exception {
        try {
            target("/test/admin").request()
                .header(AUTHORIZATION, getPrefix() + " " + getInvalidToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(WWW_AUTHENTICATE)).containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Test
    public void respondsToExpiredTokensWith401() throws Exception {
        try {
            target("/test/admin").request()
                .header(AUTHORIZATION, getPrefix() + " " + getOrdinaryGuyExpiredToken())
                .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(401);
            assertThat(e.getResponse().getHeaders().get(WWW_AUTHENTICATE)).containsOnly(getPrefix() + " realm=\"realm\"");
        }
    }

    @Override
    protected DropwizardResourceConfig getDropwizardResourceConfig() {
        return new JwtAuthTestResourceConfig();
    }

    @Override
    protected Class<JwtAuthTestResourceConfig> getDropwizardResourceConfigClass() {
        return JwtAuthTestResourceConfig.class;
    }

    @Override
    protected String getPrefix() {
        return BEARER_PREFIX;
    }

    @Override
    protected String getOrdinaryGuyValidToken() {
        return toToken(SECRET, claimsForUser(ORDINARY_USER));
    }

    @Override
    protected String getOrdinaryGuyExpiredToken() {
        final JWTClaimsSet.Builder claims = claimsForUser(ORDINARY_USER);
        claims.expirationTime(Date.from(Instant.now().minus(10, ChronoUnit.SECONDS)));
        return toToken(SECRET, claims);
    }

    @Override
    protected String getGoodGuyValidToken() {
        return toToken(SECRET, claimsForUser(ADMIN_USER));
    }

    @Override
    protected String getBadGuyToken() {
        return toToken(SECRET, claimsForUser(BADGUY_USER));
    }

    @Override
    protected String getInvalidToken() {
        byte[] invalidKey = Base64.getDecoder().decode("nOFk+pMZ6+/krRXRBpu9sN4D4oEQKZo6I2Nbfx5whjIKKldkGn02LdA8KIgEnvvNiKfmOzLs6JLm0Z85eEqivw==");
        return toToken(invalidKey, claimsForUser(BADGUY_USER));
    }

    private JWTClaimsSet.Builder claimsForUser(String user) {
        final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        claims.expirationTime(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)));
        claims.subject(user);
        claims.issuer("Issuer");
        claims.audience("Audience");
        return claims;
    }

    private String toToken(byte[] key, JWTClaimsSet.Builder claims) {
        try {
            JWSSigner signer = new MACSigner(key);

            // Prepare JWS object with "Hello, world!" payload
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(claims.build().toJSONObject()));

            // Apply the HMAC
            jwsObject.sign(signer);

            return jwsObject.serialize();
        }
        catch (JOSEException e) { throw Throwables.propagate(e); }
    }

}

package com.github.toastshaman.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.google.common.cache.CacheBuilderSpec;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.PrincipalImpl;
import org.junit.Before;
import org.junit.Test;

import java.security.Principal;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class JwtCachingAuthenticatorTest {

    @SuppressWarnings("unchecked")
    private final Authenticator<JWTClaimsSet, Principal> underlying = mock(Authenticator.class);

    private final CachingJwtAuthenticator<Principal> cached = new CachingJwtAuthenticator<>(new MetricRegistry(),
        underlying, CacheBuilderSpec.parse("maximumSize=1"));

    private static final byte[] SECRET = Base64.getDecoder().decode("lbZXcYmcZmhrZWYq7ows3kgqeiFuhPwWsbkoNoVWYN0=");

    private final ConfigurableJWTProcessor<SecurityContext> consumer;

    public JwtCachingAuthenticatorTest() {
        this.consumer = new DefaultJWTProcessor<>();

        JWKSource<SecurityContext> keySource = new ImmutableSecret<>(SECRET);
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS512, keySource);
        consumer.setJWSKeySelector(keySelector);
    }

    private JWTClaimsSet tokenOne() {
        final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        claims.subject("good-guy");
        claims.issuer("Issuer");
        claims.audience("Audience");

        return claims.build();
    }

    private JWTClaimsSet tokenTwo() {
        final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        claims.subject("good-guy-two");
        claims.issuer("Issuer");
        claims.audience("Audience");

        return claims.build();
    }

    @Before
    public void setUp() throws Exception {
        when(underlying.authenticate(any(JWTClaimsSet.class)))
            .thenReturn(Optional.<Principal>of(new PrincipalImpl("principal")));
    }

    @Test
    public void cachesTheFirstReturnedPrincipal() throws Exception {
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));

        verify(underlying, times(1)).authenticate(any(JWTClaimsSet.class));
    }

    @Test
    public void doesNotCacheDifferingTokens() throws Exception {
        assertThat(cached.authenticate(tokenOne())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));
        assertThat(cached.authenticate(tokenTwo())).isEqualTo(Optional.<Principal>of(new PrincipalImpl("principal")));

        verify(underlying, times(2)).authenticate(any(JWTClaimsSet.class));
    }
}

package com.github.toastshaman.dropwizard.auth.jwt.example;

import com.github.toastshaman.dropwizard.auth.jwt.JwtAuthFilter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.dropwizard.Application;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import java.security.Principal;
import java.util.Optional;

import static java.math.BigDecimal.ONE;

/**
 * A sample dropwizard application that shows how to set up the JWT Authentication provider.
 * <p/>
 * The Authentication Provider will parse the tokens supplied in the "Authorization" HTTP header in each HTTP request
 * given your resource is protected with the @Auth annotation.
 */
public class JwtAuthApplication extends Application<MyConfiguration> {

    @Override
    public void initialize(Bootstrap<MyConfiguration> configurationBootstrap) {}

    @Override
    public void run(MyConfiguration configuration, Environment environment) throws Exception {
        final byte[] key = configuration.getJwtTokenSecret();

        final ConfigurableJWTProcessor<SecurityContext> consumer = new DefaultJWTProcessor<>();

        JWKSource<SecurityContext> keySource = new ImmutableSecret<>(key);
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, keySource);
        consumer.setJWSKeySelector(keySelector);

//            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
//            .setRequireExpirationTime() // the JWT must have an expiration time
//            .setRequireSubject() // the JWT must have a subject claim
//            .setVerificationKey(new HmacKey(key)) // verify the signature with the public key
//            .setRelaxVerificationKeyValidation() // relaxes key length requirement
//            .build(); // create the JwtConsumer instance

        environment.jersey().register(new AuthDynamicFeature(
            new JwtAuthFilter.Builder<MyUser>()
                .setJwtConsumer(consumer)
                .setRealm("realm")
                .setPrefix("Bearer")
                .setAuthenticator(new ExampleAuthenticator())
                .buildAuthFilter()));

        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(Principal.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
        environment.jersey().register(new SecuredResource(configuration.getJwtTokenSecret()));
    }

    private static class ExampleAuthenticator implements Authenticator<JWTClaimsSet, MyUser> {

        @Override
        public Optional<MyUser> authenticate(JWTClaimsSet context) {
            // Provide your own implementation to lookup users based on the principal attribute in the
            // JWT Token. E.g.: lookup users from a database etc.
            // This method will be called once the token's signature has been verified

            // In case you want to verify different parts of the token you can do that here.
            // E.g.: Verifying that the provided token has not expired.

            // All JsonWebTokenExceptions will result in a 401 Unauthorized response.

            final String subject = context.getSubject();
            if ("good-guy".equals(subject)) {
                return Optional.of(new MyUser(ONE, "good-guy"));
            }
            return Optional.empty();
        }
    }

    public static void main(String[] args) throws Exception {
        new JwtAuthApplication().run("server");
    }
}

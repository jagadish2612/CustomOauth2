package com.example.demo.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import com.example.demo.entity.Account;
import com.example.demo.service.AccountService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthServerConfig {

    @Autowired
    private AccountService accountService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        // http.exceptionHandling(exception ->
        // exception.defaultAuthenticationEntryPointFor(
        // new LoginUrlAuthenticationEntryPoint("/login"), // Ensure that this path is
        // valid
        // new MediaTypeRequestMatcher(MediaType.TEXT_HTML))); // Adjusted for handling
        // HTML login flows

        // http.oauth2ResourceServer(rserver -> rserver.jwt(Customizer.withDefaults()));
        // // For resource server handling
        // JWTs

        http.cors(cors -> cors.disable()).csrf(csrf -> csrf.disable());

        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(
                        authorizeRequests -> authorizeRequests
                                .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("api-client")
                .clientSecret(passwordEncoder.encode("secret"))
                // .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PHONE)
                .scope("api.read")
                // .scope(OidcScopes.PROFILE)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/api-client")
                .redirectUri("http://127.0.0.1:8080/jagadish")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(5)).build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                Set<String> authorizedScopes = context.getAuthorizedScopes();
                if (authorizedScopes.contains("phone")) {
                    // Extract the user principal (e.g., username) from the context
                    String username = context.getPrincipal().getName();

                    // Query the user repository for the user details
                    accountService.findByEmail(username).ifPresent(user -> {
                        // Dynamically add phone-related claims
                        context.getClaims().claim("phone_number", user.getPhonenumber());
                        context.getClaims().claim("phone_number_verified", user.getPhonenumberverified());
                    });
                }
            }
        };
    }

    @Bean
    public static JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsa = generateRSA();
        JWKSet jwkSet = new JWKSet(rsa);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRSA() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRSAKey();

        RSAPublicKey publickey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publickey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }

    private static KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://auth-server:9000")
                .build();
    }
}

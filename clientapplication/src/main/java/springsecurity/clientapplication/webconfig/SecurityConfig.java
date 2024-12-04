package springsecurity.clientapplication.webconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain dSecurityFilterChain(HttpSecurity http) throws Exception {

        http.cors(cors -> cors.disable()).csrf(csrf -> csrf.disable());

        http.authorizeHttpRequests(request -> request
                .requestMatchers("/api/**").authenticated())
                .oauth2Login(oauth -> oauth.loginPage("/oauth2/authorization/api-client"))
                .oauth2Client(Customizer.withDefaults());

        return http.build();
    }

}

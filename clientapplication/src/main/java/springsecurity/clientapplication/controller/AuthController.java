package springsecurity.clientapplication.controller;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import springsecurity.clientapplication.service.JWTExtractorService;

@RestController
public class AuthController {

    @Autowired
    private WebClient webClient;

    @Autowired
    private JWTExtractorService jwtExtractorService;

    @GetMapping("/api/authenticate")
    public String authenticated() {

        return "authentication is successfull";

    }

    @GetMapping("/api/name")
    public Principal userData(Principal user) {
        return user;
    }

    @GetMapping("/api/phone")
    public Map<String, Object> userPhoneData(Principal user, @RequestHeader("Authorization") String accessToken) {
        Map<String, Object> userInfo = new HashMap<>();

        // Add user info (from Principal or access token)
        userInfo.put("user", user);

        // Extract phone-related claims from the Access Token (or ID Token)
        try {
            String phoneNumber = jwtExtractorService.getPhoneNumber(accessToken); // Extract from token
            Boolean phoneVerified = jwtExtractorService.isPhoneVerified(accessToken); // Extract from token

            userInfo.put("phone_number", phoneNumber);
            userInfo.put("phone_verified", phoneVerified);
        } catch (Exception e) {
            userInfo.put("error", "Failed to extract phone info: " + e.getMessage());
        }

        return userInfo;
    }

    @GetMapping("/api/users")
    public String[] getUsers(
            @RegisteredOAuth2AuthorizedClient("api-client-authorization-code") OAuth2AuthorizedClient client) {

        System.out.println("Access Token: " + client.getAccessToken().getTokenValue());

        return this.webClient
                .get()
                .uri("http://127.0.0.1:7070/api/users")
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

}

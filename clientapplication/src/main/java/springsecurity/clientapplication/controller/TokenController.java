// package springsecurity.clientapplication.controller;

// import java.util.Map;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.RequestParam;
// import org.springframework.web.bind.annotation.RestController;

// import springsecurity.clientapplication.service.JWTExtractorService;

// @RestController
// public class TokenController {

// @Autowired
// private JWTExtractorService jwtExtractorService;

// @GetMapping("/decode-id-token")
// public Map<String, Object> decodeIdToken(@RequestParam String idToken) {
// try {
// return jwtExtractorService.extractClaims(idToken);
// } catch (Exception e) {
// return Map.of("error", "Invalid token: " + e.getMessage());
// }
// }

// @GetMapping("/phone-info")
// public Map<String, Object> getPhoneInfo(@RequestParam String idToken) {
// try {
// return Map.of(
// "phone_number", jwtExtractorService.getPhoneNumber(idToken),
// "phone_verified", jwtExtractorService.isPhoneVerified(idToken));
// } catch (Exception e) {
// return Map.of("error", "Invalid token: " + e.getMessage());
// }
// }
// }

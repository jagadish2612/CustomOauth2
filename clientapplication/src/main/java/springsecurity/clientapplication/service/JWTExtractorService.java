package springsecurity.clientapplication.service;

import java.text.ParseException;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.nimbusds.jwt.SignedJWT;

@Component
public class JWTExtractorService {

    public Map<String, Object> extractClaims(String idToken) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(idToken);
        return signedJWT.getJWTClaimsSet().getClaims();
    }

    public String getPhoneNumber(String idToken) throws ParseException {
        Map<String, Object> claims = extractClaims(idToken);
        return (String) claims.get("phone_number");
    }

    public Boolean isPhoneVerified(String idToken) throws ParseException {
        Map<String, Object> claims = extractClaims(idToken);
        return (Boolean) claims.get("phone_number_verified");
    }
}

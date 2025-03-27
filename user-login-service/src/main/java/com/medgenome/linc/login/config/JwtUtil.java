package com.medgenome.linc.login.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

    // Secure key for HS256
    private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private final long EXPIRATION_TIME = 600000; // 10 minutes
    private final long OTP_EXPIRATION_TIME = 5 * 60 * 1000; // 5 Minutes for OTP

    //Generate JWT token
    public String generateToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //Validate JWT token
    public boolean validateToken(String token, String userName) {
        return userName.equals(extractUsername(token)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date expiration = extractClaim(token, Claims::getExpiration);
        return expiration.before(new Date());
    }

    public String generateResetToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 900000)) // 15 minutes
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000)) // 24 hours
                .signWith(secretKey)
                .compact();
    }

    //Method to Validate Token Without Expiration Check
    public boolean validateTokenWithoutExpiration(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }



    // -------------------- New Methods for OTP --------------------

    // Generate JWT Token with OTP
    public String generateOtpToken(String emailOrPhone, String otp) {

        String otpToken = Jwts.builder()
                .setSubject(emailOrPhone)
                .claim("otp", otp)
                .setExpiration(new Date(System.currentTimeMillis() + OTP_EXPIRATION_TIME))
                .signWith(secretKey)
                .compact();
        System.out.println("otpToken:   " + otpToken);
        return  otpToken;
    }

    // Extract OTP from Token
    public String extractOtp(String token) {
        return extractClaim(token, claims -> claims.get("otp", String.class));
    }

    // Extract Email or Phone from Token
    public String extractEmailOrPhone(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Validate OTP Token
    public boolean validateOtpToken(String token, String providedOtp) {
        try {
            if (isTokenExpired(token)) {
                throw new RuntimeException("Token has expired.");
            }
            String storedOtp = extractOtp(token);
            return storedOtp.equals(providedOtp);
        } catch (Exception e) {
            throw new RuntimeException("Invalid OTP token: " + e.getMessage());
        }
    }

    // Generic method to extract claims
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }

}

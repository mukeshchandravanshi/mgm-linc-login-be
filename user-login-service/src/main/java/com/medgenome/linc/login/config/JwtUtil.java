package com.medgenome.linc.login.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    // Use the secretKeyFor method to create a secure key for HS256
    private  final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256); // 256-bit key

    private final long EXPIRATION_TIME = 600000; // 1 hour in milliseconds

    public  String generateToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey)
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token, String userName) {
        return userName.equals(extractUsername(token)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date expiration = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        System.out.println("Token expiration time: " + expiration);
        return expiration.before(new Date());
    }

    public String generateResetToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + 900000)) // 15 minutes
                .signWith(secretKey)
                .compact();
    }


}

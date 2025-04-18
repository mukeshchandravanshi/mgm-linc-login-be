
package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.JwtUtil;
import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.TokenRequest;
import com.medgenome.linc.login.model.TokenResponse;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.util.UserObjectUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final OtpUtil otpUtil;
    private final JwtUtil jwtUtil;

    public Map<String, String> verifyOtp(String emailOrPhone, String otp) {
        System.out.println("emailOrPhone" + emailOrPhone);
        System.out.println("otp" + otp);
        if (otp == null || otp.isBlank()) {
            throw new RuntimeException("OTP is required.");
        }

        boolean validOtp = otpUtil.validateOtp(emailOrPhone, otp);
        System.out.println("validOtp" + validOtp);

        if (!validOtp) {
            throw new RuntimeException("Invalid or expired OTP.");
        }

        // Check if the user exists in temporary storage for registration
        User tempUser = UserObjectUtil.getUser(emailOrPhone);
        System.out.println("tempUser" + tempUser);
        if (tempUser != null) {
            return registerUser(tempUser, emailOrPhone);
        } else {
            return generateLoginToken(emailOrPhone);
        }
    }

    private Map<String, String> registerUser(User tempUser, String emailOrPhone) {
        try {
            User registeredUser = userService.registerUser(tempUser);
            if (registeredUser != null) {
                UserObjectUtil.removeUser(emailOrPhone);
                return Map.of("message", "User registered successfully!");
            }
            throw new RuntimeException("User registration failed.");
        } catch (Exception e) {
            throw new RuntimeException("An error occurred during registration: " + e.getMessage());
        }
    }

    private Map<String, String> generateLoginToken(String emailOrPhone) {
        String loginToken = jwtUtil.generateToken(emailOrPhone);
        return Map.of("token", loginToken, "message", "Login successful!");
    }

    public ResponseEntity<TokenResponse> refreshToken(TokenRequest tokenRequest) {
        String refreshToken = tokenRequest.getRefreshToken();
        try {
            // Validate first
            if (!jwtUtil.validateTokenWithoutExpiration(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new TokenResponse(null, null, "Invalid refresh token."));
            }

            // Extract username safely after validation
            String username = jwtUtil.extractUsername(refreshToken);

            Optional<User> userOpt = userService.findByUserName(username);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new TokenResponse(null, null, "User not found."));
            }

            String accessToken = jwtUtil.generateToken(username);
            String newRefreshToken = jwtUtil.generateRefreshToken(username);

            return ResponseEntity.ok(new TokenResponse(accessToken, newRefreshToken, "Token refreshed successfully."));

        } catch (ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenResponse(null, null, "Refresh token expired. Please log in again."));
        } catch (MalformedJwtException | IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenResponse(null, null, "Invalid refresh token format."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new TokenResponse(null, null, "An error occurred while refreshing the token."));
        }

    }
}

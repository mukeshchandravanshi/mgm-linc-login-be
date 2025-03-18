package com.medgenome.linc.login.controller;


import com.medgenome.linc.login.config.JwtUtil;
import com.medgenome.linc.login.model.ForgotPasswordRequest;
import com.medgenome.linc.login.model.Role;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.service.EmailService;
import com.medgenome.linc.login.service.SmsService;
import com.medgenome.linc.login.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private  final SmsService smsService;

    @Value("${app.reset-password-url}")
    private String resetPasswordUrl;

    public AuthController(UserService userService, JwtUtil jwtUtil, PasswordEncoder passwordEncoder, EmailService emailService, SmsService smsService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.smsService = smsService;
    }

    @PostMapping("/register")
    public Map<String, String> register(@RequestBody User request) {
        System.out.println("payload"+request);
        String userName = request.getEmail() != null ? request.getEmail() : request.getPhoneNum();
        String password = request.getPassword();

        if (userName == null || password == null) {
            throw new RuntimeException("Username and password are required.");
        }

        if (userService.findByUserName(userName).isPresent()) {
            throw new RuntimeException(userName+ " username already exists.");
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(userName) // Assuming username is email
                .phoneNum(request.getPhoneNum())
                .role(Role.USER)
                .country(request.getCountry())
                .password(passwordEncoder.encode(password))
                .build();

        System.out.println("encodedUser:  "+user);
        userService.registerUser(user);

        String token = jwtUtil.generateToken(userName);
        System.out.println("jwtToken: " + token);
        return Map.of("token", token,  "message", "You are successfully registered to MedGenome....");
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User request) {
        String email = request.getEmail();
        String phoneNum = request.getPhoneNum();
        String password = request.getPassword();

        // Define regex patterns for email and phone validation
        String emailRegex = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        String phoneRegex = "^\\+?[0-9\\-\\s]{7,15}$";

        if (email != null && !Pattern.matches(emailRegex, email)) {
            throw new RuntimeException("Invalid email format.");
        }

        if (phoneNum != null && !Pattern.matches(phoneRegex, phoneNum)) {
            throw new RuntimeException("Invalid phone number format.");
        }

        String userName = email != null ? email : phoneNum;

        Optional<User> userOpt = userService.findByUserName(userName);

        if (userOpt.isEmpty()) {
            throw new RuntimeException(email != null ? "Invalid email." : "Invalid phone number.");
        }

        User user = userOpt.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password.");
        }

        String token = jwtUtil.generateToken(userName);
        return Map.of("token", token, "message", "Welcome to MedGenome!");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            String emailOrPhone = request.getEmailOrPhone();
            Optional<User> userOpt = userService.findByUserName(emailOrPhone);

            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User not found with provided email or phone number."));
            }

            User user = userOpt.get();
            String token = jwtUtil.generateResetToken(user.getUsername());
            String resetUrl = resetPasswordUrl + token;
            String message = "Click the link to reset your password: ";
            String subjectMessage = "Password Reset Request";

            if (emailOrPhone.contains("@")) {
                emailService.sendResetPasswordEmail(user.getEmail(), subjectMessage, message + resetUrl);
            } else {
                try {
                    smsService.sendSms(user.getPhoneNum(), "Reset your password using this link: " + resetUrl);
                } catch (Exception smsException) {
                    System.err.println("AuthController: Failed to send SMS : " + smsException.getMessage());
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of("message", "Failed to send SMS. Please try again later."));
                }
            }

            return ResponseEntity.ok(Map.of("message", "Password reset link sent successfully!"));
        } catch (Exception emailException) {
            System.err.println("AuthController: Failed to send EMAIL: " + emailException.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to send Email. Please try again later.."));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestBody Map<String, String> request) {
        String newPassword = request.get("newPassword");
        String username;

        try {
            username = jwtUtil.extractUsername(token);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid or expired token."));
        }

        User user = userService.findByUserName(username)
                .orElseThrow(() -> new RuntimeException("User not found."));

        user.setPassword(passwordEncoder.encode(newPassword));
        userService.updateUser(user);

        return ResponseEntity.ok(Map.of("message", "Password reset successfully!"));
    }
}

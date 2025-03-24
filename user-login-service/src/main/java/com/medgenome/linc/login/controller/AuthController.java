package com.medgenome.linc.login.controller;


import com.medgenome.linc.login.config.JwtUtil;
import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.*;
import com.medgenome.linc.login.service.EmailService;
import com.medgenome.linc.login.service.SmsService;
import com.medgenome.linc.login.service.UserService;
import com.medgenome.linc.login.util.validator.EmailAndPhoneValidator;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private  final SmsService smsService;
    private  final OtpUtil otpUtil;
    private final EmailAndPhoneValidator emailAndPhoneValidator;

    @Value("${app.reset-password-url}")
    private String resetPasswordUrl;

    public AuthController(UserService userService, JwtUtil jwtUtil, PasswordEncoder passwordEncoder, EmailService emailService, SmsService smsService, OtpUtil otpUtil, EmailAndPhoneValidator emailAndPhoneValidator) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.smsService = smsService;
        this.otpUtil = otpUtil;
        this.emailAndPhoneValidator = emailAndPhoneValidator;
    }

    @PostMapping("/register")
    public Map<String, String> register(@RequestBody User request) {
        System.out.println("Payload: " + request);

        String userName = request.getEmail() != null ? request.getEmail() : request.getPhoneNum();
        String password = request.getPassword();
        String confirmPassword = request.getConfirmPassword();

        // Validate required fields
        if (userName == null || password == null || confirmPassword == null) {
            throw new RuntimeException("Username, createPasswd, and confirmPasswd are required.");
        }

        // Validate if passwords match
        if (!password.equals(confirmPassword)) {
            throw new RuntimeException("Password and Confirm Password do not match.");
        }

        // Check if user already exists
        if (userService.findByUserName(userName).isPresent()) {
            throw new RuntimeException(userName + " username already exists.");
        }

        // Build User object using builder pattern
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .phoneNum(request.getPhoneNum())
                .role(Role.USER)
                .country(request.getCountry())
                .accountName(request.getAccountName())
                .status(Status.ACTIVE)
                .password(passwordEncoder.encode(password))
                .build();

        System.out.println("Encoded User: " + user);
        userService.registerUser(user);

        // Generate JWT Token
        String token = jwtUtil.generateToken(userName);
        System.out.println("JWT Token: " + token);

        return Map.of("token", token, "message", "You are successfully registered to MedGenome.");
    }


    @PostMapping("/loginOld")
    public Map<String, String> loginOld(@RequestBody User request) {
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

            // OTP based
            String otp = otpUtil.generateOtp(emailOrPhone);
            String message = "You have requested to reset your password. Use the OTP below to proceed with the reset: ";
            String subjectMessage = "Password Reset Request";

            if (emailOrPhone.contains("@")) {
                emailService.sendResetPasswordEmail(user.getEmail(), subjectMessage, message + otp);
            } else {
                try {
                    smsService.sendSms(user.getPhoneNum(), "Reset your password using this OTP: " + otp);
                } catch (Exception smsException) {
                    System.err.println("AuthController: Failed to send SMS : " + smsException.getMessage());
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of("message", "Failed to send SMS. Please try again later."));
                }
            }

            return ResponseEntity.ok(Map.of("message", "Password reset OTP sent successfully!"));
        } catch (Exception emailException) {
            System.err.println("AuthController: Failed to send EMAIL: " + emailException.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to send Email. Please try again later.."));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody User request) {
        String email = request.getEmail();
        String phoneNum = request.getPhoneNum();
        String password = request.getPassword();

        // Validate email or phone number format
        emailAndPhoneValidator.validateEmailAndPhone(email, phoneNum);

        String emailOrPhone = email != null ? email : phoneNum;
        Optional<User> userOpt = userService.findByUserName(emailOrPhone);

        if (userOpt.isEmpty()) {
            throw new RuntimeException(email != null ? "Invalid email." : "Invalid phone number.");
        }

        User user = userOpt.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password.");
        }

        // Generate OTP
        String otp = otpUtil.generateOtp(emailOrPhone);
        String message = "You have requested for login OTP. Use the OTP below to proceed with the login: ";
        String subjectMessage = "Login OTP";

        boolean emailSent = false;
        boolean smsSent = false;

        // Send OTP via Email
        try {
            emailService.sendResetPasswordEmail(user.getEmail(), subjectMessage, message + otp);
            emailSent = true;
        } catch (Exception emailException) {
            System.err.println("AuthController: Failed to send EMAIL: " + emailException.getMessage());
        }

        // Send OTP via SMS
        try {
            smsService.sendSms(user.getPhoneNum(), "Login using OTP: " + otp);
            smsSent = true;
        } catch (Exception smsException) {
            System.err.println("AuthController: Failed to send SMS: " + smsException.getMessage());
        }

        // Response Handling
        if (!emailSent && !smsSent) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to send OTP via both Email and SMS. Please try again later."));
        } else if (!emailSent) {
            return ResponseEntity.ok(Map.of("message", "OTP sent successfully via SMS. Failed to send via Email."));
        } else if (!smsSent) {
            return ResponseEntity.ok(Map.of("message", "OTP sent successfully via Email. Failed to send via SMS."));
        }
        return ResponseEntity.ok(Map.of("message", "OTP sent successfully via Email and SMS!"));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(@RequestBody OtpVerificationRequest request) {
        String otp = request.getOtp();

        if (otp == null || otp.isBlank()) {
            throw new RuntimeException("OTP is required.");
        }

        // Find emailOrPhone using the OTP from the OTP storage
        String emailOrPhone = otpUtil.getEmailOrPhoneFromOtp(otp);

        if (emailOrPhone == null) {
            throw new RuntimeException("Invalid or expired OTP.");
        }

        // Validate OTP
        boolean isValidOtp = otpUtil.validateOtp(emailOrPhone, otp);

        if (!isValidOtp) {
            throw new RuntimeException("Invalid or expired OTP.");
        }

        // Generate JWT Token for login
        String loginToken = jwtUtil.generateToken(emailOrPhone);
        return ResponseEntity.ok(Map.of("token", loginToken, "message", "Login successful!"));
    }






//    @PostMapping("/login-another-way")
//    public Map<String, String> loginAnotherWay(@RequestBody User request) {
//        String emailOrPhone = request.getEmail()!=null?request.getEmail():request.getPhoneNum();
//        if (emailOrPhone == null || emailOrPhone.isBlank()) {
//            throw new RuntimeException("Email or phone number is required.");
//        }
//
//        // Validate email or phone number format
//        if (emailOrPhone.contains("@")) {
//            if (!Pattern.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", emailOrPhone)) {
//                throw new RuntimeException("Invalid email format.");
//            }
//        } else {
//            if (!Pattern.matches("^\\+?[0-9\\-\\s]{7,15}$", emailOrPhone)) {
//                throw new RuntimeException("Invalid phone number format.");
//            }
//        }
//
//        Optional<User> userOpt = userService.findByUserName(emailOrPhone);
//
//        if (userOpt.isEmpty()) {
//            throw new RuntimeException("No user found with the provided email or phone number.");
//        }
//
//        // Generate and send OTP
//        String otp = otpService.generateOtp(emailOrPhone);
//        otpService.sendOtp(emailOrPhone, otp);
//
//        return Map.of("message", "OTP has been sent to your registered contact.");
//    }


//    @PostMapping("/reset-password")
//    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
//        log.info("Reset password payload: {}", request);
//        try {
//            String emailOrPhone = request.getEmailOrPhone();
//            String otp = request.getOtp();
//            String oldPassword = request.getOldPassword();
//            String newPassword = request.getNewPassword();
//            String confirmPassword = request.getConfirmPassword();
//
//            // Check if user exists
//            Optional<User> userOpt = userService.findByUserName(emailOrPhone);
//            if (userOpt.isEmpty()) {
//                return ResponseEntity.status(HttpStatus.NOT_FOUND)
//                        .body(Map.of("message", "User not found with provided email or phone number."));
//            }
//
//            User user = userOpt.get();
//
//            // Validate OTP
//            if (!otpService.validateOtp(emailOrPhone, otp)) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "Invalid or expired OTP."));
//            }
//
//            // Validate Old Password - Ensure it matches the stored password
//            if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "Old password is incorrect."));
//            }
//
//            // Check if New Password and Confirm Password match
//            if (!newPassword.equals(confirmPassword)) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "New password and Confirm password do not match."));
//            }
//
//            // Prevent Reuse of Old Password
//            if (passwordEncoder.matches(newPassword, user.getPassword())) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "New password cannot be the same as the current password."));
//            }
//
//            // Update password securely
//            user.setPassword(passwordEncoder.encode(newPassword));
//            userService.registerUser(user);
//
//            return ResponseEntity.ok(Map.of("message", "Password reset successfully!"));
//        } catch (Exception e) {
//            e.printStackTrace();
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                    .body(Map.of("message", "Failed to reset password. Please try again later."));
//        }
//    }

//    @PostMapping("/reset-password")
//    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
//        log.info("Reset password payload: {}", request);
//        try {
//            String otp = request.getOtp();
//            String oldPassword = request.getOldPassword();
//            String newPassword = request.getNewPassword();
//            String confirmPassword = request.getConfirmPassword();
//
//            // Extract Email or Phone using OTP validation
//            Optional<User> userOpt = userService.findByUserName(emailOrPhone);
//
//            if (userOpt.isEmpty()) {
//                return ResponseEntity.status(HttpStatus.NOT_FOUND)
//                        .body(Map.of("message", "User not found with provided OTP."));
//            }
//
//            User user = userOpt.get();
//            String emailOrPhone = user.getEmail() != null ? user.getEmail() : user.getPhoneNum();
//
//            // Validate OTP
//            if (!otpUtil.validateOtp(emailOrPhone, otp)) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "Invalid or expired OTP."));
//            }
//
//            // Validate Old Password - Ensure it matches the stored password
//            if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "Old password is incorrect."));
//            }
//
//            // Check if New Password and Confirm Password match
//            if (!newPassword.equals(confirmPassword)) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "New password and Confirm password do not match."));
//            }
//
//            // Prevent Reuse of Old Password
//            if (passwordEncoder.matches(newPassword, user.getPassword())) {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body(Map.of("message", "New password cannot be the same as the current password."));
//            }
//
//            // Update password securely
//            user.setPassword(passwordEncoder.encode(newPassword));
//            userService.registerUser(user);
//
//            return ResponseEntity.ok(Map.of("message", "Password reset successfully!"));
//        } catch (Exception e) {
//            e.printStackTrace();
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                    .body(Map.of("message", "Failed to reset password. Please try again later."));
//        }
//    }


}

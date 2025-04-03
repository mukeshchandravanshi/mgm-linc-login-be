package com.medgenome.linc.login.controller;

import com.medgenome.linc.login.model.*;
import com.medgenome.linc.login.service.*;
import com.medgenome.linc.login.validator.ExistingUserValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/v1/auth")
@Slf4j
public class AuthController {

    private final SignUpService signUpService;
    private final AuthService authService;
    private final SendOtpService sendOtpService;
    private final UserService userService;
    private final PasswordService passwordService;
    private final ExistingUserValidator existingUserValidator;


    @Value("${app.reset-password-url}")
    private String resetPasswordUrl;

    public AuthController(SignUpService signUpService, AuthService authService, SendOtpService sendOtpService, UserService userService, PasswordService passwordService, ExistingUserValidator existingUserValidator) {
        this.signUpService = signUpService;
        this.authService = authService;
        this.sendOtpService = sendOtpService;
        this.userService = userService;
        this.passwordService = passwordService;
        this.existingUserValidator = existingUserValidator;
    }

    @PostMapping("/sign-up")
    public ResponseEntity<Map<String, String>> signUp(@RequestBody User request) {
        signUpService.registerUser(request);
        return ResponseEntity.ok(Map.of("message", "User registration initiated. OTP sent successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request) {
        existingUserValidator.validateUserExists(request.getEmailOrPhone());
        // Create a SendOtpRequest based on the incoming LoginRequest
        SendOtpRequest sendOtpRequest = new SendOtpRequest();
        sendOtpRequest.setEmailOrPhone(request.getEmailOrPhone());
        sendOtpRequest.setPassword(request.getPassword());
        Map<String, String> otpResponse = sendOtpService.sendOtp(sendOtpRequest);
        return ResponseEntity.ok(otpResponse);
    }

    @PostMapping("/login-another-way")
    public ResponseEntity<Map<String, String>> loginAnotherWay(@RequestBody LoginAnotherWayRequest request) {
        existingUserValidator.validateUserExists(request.getEmailOrPhone());
        SendOtpRequest sendOtpRequest = new SendOtpRequest();
        sendOtpRequest.setEmailOrPhone(request.getEmailOrPhone());
        Map<String, String> response = sendOtpService.sendOtp(sendOtpRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(@RequestBody OtpVerificationRequest request) {
        String emailOrPhone = request.getEmailOrPhone();
        System.out.println("verify-otp-emailOrPhone" + emailOrPhone);
        String otp = request.getOtp();
        Map<String, String> response = authService.verifyOtp(emailOrPhone, otp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        SendOtpRequest sendOtpRequest = new SendOtpRequest();
        sendOtpRequest.setEmailOrPhone(request.getEmailOrPhone());
        Map<String, String> response = sendOtpService.sendOtp(sendOtpRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<Map<String, String>> resendOtp(@RequestBody SendOtpRequest request) {
        Map<String, String> response = sendOtpService.sendOtp(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody ResetPasswordRequest request) {
        Map<String, String> response = passwordService.handlePasswordReset(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody TokenRequest tokenRequest) {
        return authService.refreshToken(tokenRequest);
    }

//    @PostMapping("/send-otp")
//    public ResponseEntity<Map<String, String>> sendOtp(@RequestBody User request) {
//        return ResponseEntity.ok(sendOtpService.handleOtpSending(request));
//    }

}

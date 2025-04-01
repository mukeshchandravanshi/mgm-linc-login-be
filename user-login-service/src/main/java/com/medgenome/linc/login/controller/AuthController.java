package com.medgenome.linc.login.controller;

import com.medgenome.linc.login.model.*;
import com.medgenome.linc.login.service.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/v1/auth")
@Slf4j
public class AuthController {

    private  final SignUpService signUpService;
    private final AuthService authService;
    private final ForgotPasswordService forgotPasswordService;
    private final LoginService loginService;
    private final LoginAnOtherWayService loginAnOtherWayService;
    private final SendOtpService sendOtpService;
    private final UserService userService;
    private final ResentOtpService resentOtpService;
    private final PasswordService passwordService;


    @Value("${app.reset-password-url}")
    private String resetPasswordUrl;

    public AuthController(SignUpService signUpService, AuthService authService, ForgotPasswordService forgotPasswordService, LoginService loginService, LoginAnOtherWayService loginAnOtherWayService, SendOtpService sendOtpService, UserService userService, ResentOtpService resentOtpService, PasswordService passwordService) {
        this.signUpService = signUpService;
        this.authService = authService;
        this.forgotPasswordService = forgotPasswordService;
        this.loginService = loginService;
        this.loginAnOtherWayService = loginAnOtherWayService;
        this.sendOtpService = sendOtpService;
        this.userService = userService;
        this.resentOtpService = resentOtpService;
        this.passwordService = passwordService;
    }

    @PostMapping("/sign-up")
    public ResponseEntity<Map<String, String>> signUp(@RequestBody User request) {
        signUpService.registerUser(request);
        return ResponseEntity.ok(Map.of("message", "User registration initiated. OTP sent successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody User request) {
        Map<String, String> response = loginService.handleLogin(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login-another-way")
    public ResponseEntity<Map<String, String>> loginAnotherWay(@RequestBody User request) {
        Map<String, String> response = loginAnOtherWayService.sendOtp(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(@RequestBody OtpVerificationRequest request) {
        String emailOrPhone = request.getEmailOrPhone();
        System.out.println("verify-otp-emailOrPhone"+emailOrPhone);
        String otp = request.getOtp();

        Map<String, String> response = authService.verifyOtp(emailOrPhone, otp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        Map<String, String> response = forgotPasswordService.handleForgotPassword(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<Map<String, String>> resendOtp(@RequestBody ResendOtpRequest request) {
        String emailOrPhone = request.getEmailOrPhone();

        // Find user safely
        User user = userService.findByUserName(emailOrPhone)
                .orElseThrow(() -> new RuntimeException("User not found with provided email or phone number."));

        // Call the reusable OTP method
        Map<String, String> response = resentOtpService.generateAndSendOtp(user, emailOrPhone, "Resend OTP");
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

    @PostMapping("/send-otp")
    public ResponseEntity<Map<String, String>> sendOtp(@RequestBody User request) {
        return ResponseEntity.ok(sendOtpService.handleOtpSending(request));
    }

}

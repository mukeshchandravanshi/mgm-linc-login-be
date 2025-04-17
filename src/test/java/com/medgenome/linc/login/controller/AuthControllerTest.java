package com.medgenome.linc.login.controller;

import com.medgenome.linc.login.model.*;
import com.medgenome.linc.login.service.*;
import com.medgenome.linc.login.validator.UserValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

public class AuthControllerTest {

    @Mock
    private SignUpService signUpService;
    @Mock
    private AuthService authService;
    @Mock
    private SendOtpService sendOtpService;
    @Mock
    private PasswordService passwordService;
    @Mock
    private UserValidator userValidator;

    @InjectMocks
    private AuthController authController;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testSignUp() {
        User user = new User();
        doNothing().when(signUpService).signUpUser(user);

        ResponseEntity<Map<String, String>> response = authController.signUp(user);
        assertEquals("User registration initiated. OTP sent successfully!", response.getBody().get("message"));
    }

    @Test
    public void testLogin() {
        LoginRequest request = new LoginRequest();
        request.setEmailOrPhone("test@example.com");
        request.setPassword("pass");

        Map<String, String> otpMap = Map.of("message", "OTP sent");
        when(sendOtpService.sendOtp(any(SendOtpRequest.class))).thenReturn(otpMap);

        ResponseEntity<Map<String, String>> response = authController.login(request);
        assertEquals("OTP sent", response.getBody().get("message"));
    }

    @Test
    public void testLoginAnotherWay() {
        LoginAnotherWayRequest request = new LoginAnotherWayRequest();
        request.setEmailOrPhone("test@example.com");

        Map<String, String> otpMap = Map.of("message", "OTP sent");
        when(sendOtpService.sendOtp(any(SendOtpRequest.class))).thenReturn(otpMap);

        ResponseEntity<Map<String, String>> response = authController.loginAnotherWay(request);
        assertEquals("OTP sent", response.getBody().get("message"));
    }

    @Test
    public void testVerifyOtp() {
        OtpVerificationRequest request = new OtpVerificationRequest();
        request.setEmailOrPhone("test@example.com");
        request.setOtp("123456");

        when(authService.verifyOtp("test@example.com", "123456"))
                .thenReturn(Map.of("message", "OTP verified"));

        ResponseEntity<Map<String, String>> response = authController.verifyOtp(request);
        assertEquals("OTP verified", response.getBody().get("message"));
    }

    @Test
    public void testForgotPassword() {
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmailOrPhone("test@example.com");

        when(sendOtpService.sendOtp(any(SendOtpRequest.class)))
                .thenReturn(Map.of("message", "OTP sent"));

        ResponseEntity<Map<String, String>> response = authController.forgotPassword(request);
        assertEquals("OTP sent", response.getBody().get("message"));
    }

    @Test
    public void testResendOtp() {
        SendOtpRequest request = new SendOtpRequest();
        request.setEmailOrPhone("test@example.com");

        when(sendOtpService.sendOtp(any(SendOtpRequest.class)))
                .thenReturn(Map.of("message", "OTP resent"));

        ResponseEntity<Map<String, String>> response = authController.resendOtp(request);
        assertEquals("OTP resent", response.getBody().get("message"));
    }

    @Test
    public void testResetPassword() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        when(passwordService.handlePasswordReset(request)).thenReturn(Map.of("message", "Password reset"));

        ResponseEntity<Map<String, String>> response = authController.resetPassword(request);
        assertEquals("Password reset", response.getBody().get("message"));
    }

    @Test
    public void testRefreshToken() {
        TokenRequest request = new TokenRequest();
        TokenResponse tokenResponse = new TokenResponse("newAccessToken", "newRefreshToken", "Success");

        when(authService.refreshToken(request)).thenReturn(ResponseEntity.ok(tokenResponse));

        ResponseEntity<TokenResponse> response = authController.refreshToken(request);
        assertEquals("Success", response.getBody().getMessage());
    }

    @Test
    public void testSendOtp() {
        SendOtpRequest request = new SendOtpRequest();
        when(sendOtpService.sendOtp(request)).thenReturn(Map.of("message", "OTP sent"));

        ResponseEntity<Map<String, String>> response = authController.sendOtp(request);
        assertEquals("OTP sent", response.getBody().get("message"));
    }
}

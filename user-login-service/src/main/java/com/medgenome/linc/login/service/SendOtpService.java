package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.SendOtpRequest;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.util.UserObjectUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SendOtpService {

    private final UserService userService;
    private final OtpUtil otpUtil;
    private final EmailService emailService;
    private final SmsService smsService;

    public Map<String, String> sendOtp(SendOtpRequest request) {
        String emailOrPhone = request.getEmailOrPhone();
        User user;
        boolean emailSent = false;
        boolean smsSent = false;

        // Determine request type using helper methods
        boolean isSignUp = UserObjectUtil.getUser(request.getEmailOrPhone()) != null;
        boolean isLoginAnotherWay = !isSignUp(request) && !isNormalLogin(request);

        // Fetch User Based on Request Type
        if (isSignUp) {
            user = UserObjectUtil.getUser(emailOrPhone); // Fetch from temporary storage
        } else {
            user = userService.findByUserName(emailOrPhone)
                    .orElseThrow(() -> new RuntimeException("User not found with provided email or phone number."));
        }

        String email = user.getEmail();
        String phoneNum = user.getPhoneNum();

        // Generate OTP
        String otp = otpUtil.generateOtp(emailOrPhone);
        String message = "You have requested an OTP. Use the OTP below to proceed: " + otp;
        String subjectMessage = "Your OTP Code";

        if (isLoginAnotherWay) {
            // Login Another Way → Send OTP ONLY to the provided Email or Phone
            if (emailOrPhone.contains("@")) {
                emailSent = sendOtpByEmail(email, subjectMessage, message);
                System.out.println("OTP sent on EMAIL : " + otp);

            } else {
                smsSent = sendOtpBySms(phoneNum, message);
                System.out.println("OTP sent on SMS : " + otp);
            }
        } else {
            // Normal Login, Forgot Password & Sign-Up → Send OTP to BOTH Email & SMS
            emailSent = sendOtpByEmail(email, subjectMessage, message);
            smsSent = sendOtpBySms(phoneNum, message);
            System.out.println("OTP sent BOTH: " + otp);
        }

        return generateOtpResponse(emailSent, smsSent);
    }

    private boolean sendOtpByEmail(String email, String subject, String message) {
        if (email == null) return false;
        try {
            emailService.sendEmail(email, subject, message);
            return true;
        } catch (Exception e) {
            System.err.println("LoginService: Failed to send Email: " + e.getMessage());
            return false;
        }
    }

    private boolean sendOtpBySms(String phoneNum, String message) {
        if (phoneNum == null) return false;
        try {
            smsService.sendSms(phoneNum, message);
            return true;
        } catch (Exception e) {
            System.err.println("LoginService: Failed to send SMS: " + e.getMessage());
            return false;
        }
    }

    private Map<String, String> generateOtpResponse(boolean emailSent, boolean smsSent) {
        if (!emailSent && !smsSent) {
            throw new RuntimeException("Failed to send OTP via both Email and SMS.");
        } else if (!emailSent) {
            return Map.of("message", "OTP sent successfully via SMS.");
        } else if (!smsSent) {
            return Map.of("message", "OTP sent successfully via Email.");
        }
        return Map.of("message", "OTP sent successfully via Email and SMS!");
    }

    //Helper Method: Checks if the request is for Sign-Up
    private boolean isSignUp(SendOtpRequest request) {
        return UserObjectUtil.getUser(request.getEmailOrPhone()) != null;
    }

    // Helper Method: Checks if the request is for Normal Login
    private boolean isNormalLogin(SendOtpRequest request) {
        return request.getPassword() != null && !request.getPassword().isBlank();
    }

    //Helper Method: Checks if the request is for Forgot Password
    private boolean isForgotPassword(SendOtpRequest request) {
        return !isSignUp(request) && request.getEmailOrPhone() != null && (request.getPassword() == null || request.getPassword().isBlank());
    }

    // Helper Method: Checks if the request is for Login Another Way
    private boolean isLoginAnotherWay(SendOtpRequest request) {
        return !isSignUp(request) && !isNormalLogin(request) && !isForgotPassword(request);
    }
}


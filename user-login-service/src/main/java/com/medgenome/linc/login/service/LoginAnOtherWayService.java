package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class LoginAnOtherWayService {

    private final UserService userService;
    private final OtpUtil otpUtil;
    private final EmailService emailService;
    private final SmsService smsService;

    public LoginAnOtherWayService(UserService userService, OtpUtil otpUtil, EmailService emailService, SmsService smsService) {
        this.userService = userService;
        this.otpUtil = otpUtil;
        this.emailService = emailService;
        this.smsService = smsService;
    }

    // Reusable OTP sending method
    public Map<String, String> sendOtp(User request) {
        String email = request.getEmail();
        String phoneNum = request.getPhoneNum();
        String emailOrPhone = email != null ? email : phoneNum;

        if (emailOrPhone == null || emailOrPhone.isBlank()) {
            throw new RuntimeException("Email or phone number is required.");
        }

        // Validate email or phone number format


        // Check if the user exists
        Optional<User> userOpt = userService.findByUserName(emailOrPhone);
        if (userOpt.isEmpty()) {
            throw new RuntimeException(email != null ? "Email not registered." : "Phone number not registered.");
        }

        // Generate OTP
        String otp = otpUtil.generateOtp(emailOrPhone);
        String subjectMessage = "Login OTP";
        String message = "You have requested a login OTP. Use the OTP below to proceed with login: " + otp;

        boolean emailSent = false;
        boolean smsSent = false;

        try {
            if (email != null) {
                emailService.sendEmail(email, subjectMessage, message);
                emailSent = true;
            }
            if (phoneNum != null) {
                smsService.sendSms(phoneNum, message);
                smsSent = true;
            }
        } catch (Exception e) {
            System.err.println("LoginService: Failed to send OTP: " + e.getMessage());
        }

        return generateOtpResponse(emailSent, smsSent);
    }

    private Map<String, String> generateOtpResponse(boolean emailSent, boolean smsSent) {
        if (!emailSent && !smsSent) {
            throw new RuntimeException("Failed to send OTP via both Email and SMS.");
        } else if (!emailSent) {
            return Map.of("message", "OTP sent successfully via SMS. Failed to send via Email.");
        } else if (!smsSent) {
            return Map.of("message", "OTP sent successfully via Email. Failed to send via SMS.");
        }
        return Map.of("message", "OTP sent successfully via Email and SMS!");
    }
}

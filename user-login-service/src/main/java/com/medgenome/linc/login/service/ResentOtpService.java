package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ResentOtpService {

    private final OtpUtil otpUtil;
    private final EmailService emailService;
    private final SmsService smsService;


    public ResentOtpService(OtpUtil otpUtil, EmailService emailService, SmsService smsService) {
        this.otpUtil = otpUtil;
        this.emailService = emailService;
        this.smsService = smsService;
    }

    public Map<String, String> generateAndSendOtp(User user, String emailOrPhone, String subjectMessage) {
        String otp = otpUtil.generateOtp(emailOrPhone);
        String message = "You have requested for login OTP. Use the OTP below to proceed with the login: " + otp;

        boolean emailSent = false;
        boolean smsSent = false;

        try {
            if (user.getEmail() != null) {
                emailService.sendEmail(user.getEmail(), subjectMessage, message);
                emailSent = true;
            }
        } catch (Exception e) {
            System.err.println("Failed to send EMAIL: " + e.getMessage());
        }

        try {
            if (user.getPhoneNum() != null) {
                smsService.sendSms(user.getPhoneNum(), message);
                smsSent = true;
            }
        } catch (Exception e) {
            System.err.println("Failed to send SMS: " + e.getMessage());
        }

        if (!emailSent && !smsSent) {
            throw new RuntimeException("Failed to send OTP via both Email and SMS. Please try again later.");
        } else if (!emailSent) {
            return Map.of("message", "OTP sent successfully via SMS. Failed to send via Email.");
        } else if (!smsSent) {
            return Map.of("message", "OTP sent successfully via Email. Failed to send via SMS.");
        }
        return Map.of("message", "OTP sent successfully via Email and SMS!");
    }
}

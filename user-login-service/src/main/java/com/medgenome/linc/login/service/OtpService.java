package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.User;

import com.medgenome.linc.login.util.validator.EmailAndPhoneValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class OtpService {

    private final EmailService emailService;
    private final SmsService smsService;
    private final OtpUtil otpUtil;
    private static final Logger logger = LoggerFactory.getLogger(OtpService.class);
    private final EmailAndPhoneValidator emailAndPhoneValidator;

    public OtpService(EmailService emailService, SmsService smsService, OtpUtil otpUtil, EmailAndPhoneValidator emailAndPhoneValidator) {
        this.emailService = emailService;
        this.smsService = smsService;
        this.otpUtil = otpUtil;
        this.emailAndPhoneValidator = emailAndPhoneValidator;
    }
    public ResponseEntity<Map<String, String>> handleOtpSending(User request) {

        String emailOrPhone = emailAndPhoneValidator.validateAndGetEmailOrPhone(request);
        boolean isNormalLogin = request.getPassword() != null && !request.getPassword().isBlank();
        return sendOtp(emailOrPhone, request, isNormalLogin);
    }

    public ResponseEntity<Map<String, String>> sendOtp(String emailOrPhone, User request, boolean isNormalLogin) {
        String otp = otpUtil.generateOtp(emailOrPhone);
        String message = "Use this OTP to proceed with the login: " + otp;
        String subjectMessage = "Login OTP";

        boolean emailSent = false;
        boolean smsSent = false;

        try {
            if (isNormalLogin) {
                // Send to both
                if (request.getEmail() != null) {
                    emailService.sendEmail(request.getEmail(), subjectMessage, message);
                    emailSent = true;
                }
                if (request.getPhoneNum() != null) {
                    smsService.sendSms(request.getPhoneNum(), message);
                    smsSent = true;
                }
            } else {
                // Send to one based on input
                if (EmailAndPhoneValidator.isEmail(emailOrPhone)) {
                    emailService.sendEmail(emailOrPhone, subjectMessage, message);
                    emailSent = true;
                } else {
                    smsService.sendSms(emailOrPhone, message);
                    smsSent = true;
                }
            }
        } catch (Exception e) {
            logger.error("Failed to send OTP for {}: {}", emailOrPhone, e.getMessage());
        }

        return handleSendOtpResponse(emailSent, smsSent, isNormalLogin);
    }

    private ResponseEntity<Map<String, String>> handleSendOtpResponse(boolean emailSent, boolean smsSent, boolean isNormalLogin) {
        if (isNormalLogin) {
            if (!emailSent && !smsSent) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("message", "Failed to send OTP via both Email and SMS."));
            }
            if (!emailSent) {
                return ResponseEntity.ok(Map.of("message", "OTP sent via SMS. Failed via Email."));
            }
            if (!smsSent) {
                return ResponseEntity.ok(Map.of("message", "OTP sent via Email. Failed via SMS."));
            }
            return ResponseEntity.ok(Map.of("message", "OTP sent via Email and SMS."));
        } else {
            return emailSent || smsSent
                    ? ResponseEntity.ok(Map.of("message", "OTP sent successfully!"))
                    : ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Failed to send OTP. Please try again later."));
        }
    }


}


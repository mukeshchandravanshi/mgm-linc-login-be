package com.medgenome.linc.login.service;
import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.ForgotPasswordRequest;
import com.medgenome.linc.login.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ForgotPasswordService {

    private final UserService userService;
    private final OtpUtil otpUtil;
    private final EmailService emailService;
    private final SmsService smsService;

    public Map<String, String> handleForgotPassword(ForgotPasswordRequest request) {
        String emailOrPhone = request.getEmailOrPhone();
        Optional<User> userOpt = userService.findByUserName(emailOrPhone);

        if (userOpt.isEmpty()) {
            throw new RuntimeException("User not found with provided email or phone number.");
        }

        return sendOtp(emailOrPhone, userOpt.get());
    }

    private Map<String, String> sendOtp(String emailOrPhone, User user) {
        String otp = otpUtil.generateOtp(emailOrPhone);
        String subjectMessage = "Password Reset OTP";
        String message = "You have requested a password reset. Use the OTP below to proceed: " + otp;

        boolean emailSent = false;
        boolean smsSent = false;

        try {
            if (user.getEmail() != null) {
                emailService.sendEmail(user.getEmail(), subjectMessage, message);
                emailSent = true;
            }
            if (user.getPhoneNum() != null) {
                smsService.sendSms(user.getPhoneNum(), message);
                smsSent = true;
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to send OTP: " + e.getMessage());
        }

        // Response Handling
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

package com.medgenome.linc.login.service;
import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.util.validator.EmailAndPhoneValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class LoginService {

    private final UserService userService;
    private final OtpUtil otpUtil;
    private final EmailService emailService;
    private final SmsService smsService;
    private final PasswordEncoder passwordEncoder;

    public Map<String, String> handleLogin(User request) {
        String email = request.getEmail();
        String phoneNum = request.getPhoneNum();
        String password = request.getPassword();
        String emailOrPhone = (email != null) ? email : phoneNum;

        // Validate email or phone format
        EmailAndPhoneValidator.validateEmailAndPhone(email, phoneNum);

        // Check if user exists
        Optional<User> userOpt = userService.findByUserName(emailOrPhone);
        if (userOpt.isEmpty()) {
            throw new RuntimeException(emailOrPhone.contains("@") ? "Email not registered." : "Phone number not registered.");
        }

        User user = userOpt.get();

        // Validate password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password.");
        }

        // Generate OTP
        String otp = otpUtil.generateOtp(emailOrPhone);
        String message = "You have requested a login OTP. Use the OTP below to proceed with login: " + otp;
        String subjectMessage = "Login OTP";

        // Send OTP
        boolean emailSent = sendOtpByEmail(user.getEmail(), subjectMessage, message);
        boolean smsSent = sendOtpBySms(user.getPhoneNum(), message);

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
            return Map.of("message", "OTP sent successfully via SMS. Failed to send via Email.");
        } else if (!smsSent) {
            return Map.of("message", "OTP sent successfully via Email. Failed to send via SMS.");
        }
        return Map.of("message", "OTP sent successfully via Email and SMS!");
    }
}


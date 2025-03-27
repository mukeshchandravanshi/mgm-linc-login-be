package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.ResetPasswordRequest;
import com.medgenome.linc.login.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class PasswordService {

    private final UserService userService;
    private final OtpUtil otpUtil;
    private final PasswordEncoder passwordEncoder;

    public PasswordService(UserService userService, OtpUtil otpUtil, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.otpUtil = otpUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public Map<String, String> handlePasswordReset(ResetPasswordRequest request) {
        String newPassword = request.getNewPassword();
        String confirmPassword = request.getConfirmPassword();
        String otp = request.getOtp();

        if (otp == null || otp.isBlank()) {
            throw new RuntimeException("OTP is required.");
        }

        if (newPassword == null || confirmPassword == null) {
            throw new RuntimeException("New password and confirm password are required.");
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new RuntimeException("New password and confirm password do not match.");
        }

        Optional<User> userOpt = userService.findByUserName(request.getEmailOrPhone());

        if (userOpt.isEmpty()) {
            throw new RuntimeException("User not found with provided OTP.");
        }

        User user = userOpt.get();
        String emailOrPhone = user.getEmail() != null ? user.getEmail() : user.getPhoneNum();

        // Validate OTP
        if (!otpUtil.validateOtp(emailOrPhone, otp)) {
            throw new RuntimeException("Invalid or expired OTP.");
        }

        // Prevent Reuse of Old Password
        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new RuntimeException("New password cannot be the same as the current password.");
        }

        // Update password securely
        user.setPassword(passwordEncoder.encode(newPassword));
        userService.registerUser(user);

        return Map.of("message", "Password reset successfully!");
    }
}

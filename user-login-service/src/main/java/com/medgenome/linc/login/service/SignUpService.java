package com.medgenome.linc.login.service;

import com.medgenome.linc.login.model.Role;
import com.medgenome.linc.login.model.Status;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.util.validator.UserObjectUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class SignUpService {

    private final UserService userService;
    private final OtpService otpService;
    private final PasswordEncoder passwordEncoder;

    public SignUpService(UserService userService,
                         UserObjectUtil userObjectUtil, OtpService otpService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.otpService = otpService;
        this.passwordEncoder = passwordEncoder;
    }

    public void registerUser(User request) {
        // Validate Input
        String emailOrPhone = Optional.ofNullable(request.getEmail()).orElse(request.getPhoneNum());

        if (emailOrPhone == null || request.getPassword() == null || request.getConfirmPassword() == null) {
            throw new RuntimeException("Email/Phone, Password, and Confirm Password are required.");
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Password and Confirm Password do not match.");
        }

        // Check User Existence
        if (userService.findByUserName(emailOrPhone).isPresent()) {
            throw new RuntimeException(emailOrPhone + " already exists. Please login or reset password.");
        }

        // Build User
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .phoneNum(request.getPhoneNum())
                .role(Role.USER)
                .country(request.getCountry())
                .accountName(request.getAccountName())
                .status(Status.ACTIVE)
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        // Save User Temporarily
        UserObjectUtil.saveUser(emailOrPhone, user);
        // Send OTP
        otpService.handleOtpSending(user);
    }
}

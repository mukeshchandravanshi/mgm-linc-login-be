package com.medgenome.linc.login.service;

import com.medgenome.linc.login.model.Role;
import com.medgenome.linc.login.model.SendOtpRequest;
import com.medgenome.linc.login.model.Status;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.validator.InputValidator;
import com.medgenome.linc.login.util.UserObjectUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class SignUpService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final SendOtpService sendOtpService;

    public SignUpService(UserService userService,PasswordEncoder passwordEncoder, SendOtpService sendOtpService) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.sendOtpService = sendOtpService;
    }

    public void registerUser(User request) {
        // Validate Input
        InputValidator.validate(request);
        String emailOrPhone = request.getEmail()!=null?request.getEmail():request.getPhoneNum();

        // Check User Existence
        if (userService.findByUserName(emailOrPhone).isPresent()) {
            throw new RuntimeException(emailOrPhone + " already exists. Please signup with another email or phone number.");
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
        System.out.println("Temp user: " + UserObjectUtil.getUser(emailOrPhone));
        // Send OTP
        // userOtpService.handleOtpSending(user);
        // Now, send OTP to the user
        SendOtpRequest sendOtpRequest = new SendOtpRequest();
        sendOtpRequest.setEmailOrPhone(emailOrPhone);
        sendOtpService.sendOtp(sendOtpRequest);

    }
}

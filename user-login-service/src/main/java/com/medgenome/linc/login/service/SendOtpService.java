package com.medgenome.linc.login.service;

import com.medgenome.linc.login.config.OtpUtil;
import com.medgenome.linc.login.model.SendOtpRequest;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.util.UserObjectUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;
import java.util.Objects;
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

       boolean isSignUp = UserObjectUtil.getUser(emailOrPhone) != null;

       // 🔍 Get the current HTTP request
       HttpServletRequest httpRequest =
               ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();

       // Extract the endpoint path
       String requestURI = httpRequest.getRequestURI();

       // Dynamically determine request type
       boolean isLoginAnotherWay = requestURI.contains("/auth/login-another-way");

       // Fetch User
       if (isSignUp) {
           user = UserObjectUtil.getUser(emailOrPhone);
       } else {
           user = userService.findByUserName(emailOrPhone)
                   .orElseThrow(() -> new RuntimeException("User not found."));
       }

       String email = user.getEmail();
       String phoneNum = user.getPhoneNum();
       String otp = otpUtil.generateOtp(emailOrPhone);
       String message = "Your OTP: " + otp;
       String subject = "OTP Code";

       //  Apply different OTP sending logic based on the detected request type
       if (isLoginAnotherWay) {
           if (emailOrPhone.contains("@")) {
               emailSent = sendOtpByEmail(email, subject, message);
               System.out.println("OTP sent on Email: "+otp);
           } else {
               smsSent = sendOtpBySms(phoneNum, message);
               System.out.println("OTP sent on SMS: "+otp);
           }
       } else {
           emailSent = sendOtpByEmail(email, subject, message);
           smsSent = sendOtpBySms(phoneNum, message);
           System.out.println("OTP sent on Both: "+otp);
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

//    private boolean sendOtpBySms(String phoneNum, String message) {
//        if (phoneNum == null) return false;
//        try {
//            smsService.sendSms(phoneNum, message);
//            return true;
//        } catch (Exception e) {
//            System.err.println("LoginService: Failed to send SMS: " + e.getMessage());
//            return false;
//        }
//    }

private boolean sendOtpBySms(String phoneNum, String message) {
    try {
        if (phoneNum != null && !phoneNum.isBlank()) {
            smsService.sendSms(phoneNum, message);
            return true;  // ✅ SMS sent successfully
        }
    } catch (Exception e) {
        System.out.println("LoginService: Failed to send SMS: " + e.getMessage());
        return false;  // ❌ SMS sending failed
    }
    return false;
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
        return !isSignUp(request) && !isNormalLogin(request);
    }
}


package com.medgenome.linc.login.config;

import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.service.UserService;
import com.medgenome.linc.login.util.UserObjectUtil;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OtpUtil {

    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final Map<String, String> otpTokenStorage = new ConcurrentHashMap<>();

    public OtpUtil(JwtUtil jwtUtil, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    public String generateOtp(String emailOrPhone) {
        // Fetch user either from DB or temporary storage
        User user = userService.findByUserName(emailOrPhone).orElse(null);

        if (user == null) {
            user = UserObjectUtil.getUser(emailOrPhone);
            if (user == null) {
                throw new RuntimeException("User not found for OTP generation.");
            }
        }

        String email = user.getEmail();
        String phone = user.getPhoneNum();

        if (email == null || phone == null) {
            throw new RuntimeException("User must have both email and phone.");
        }

        // Generate OTP
        String otp = String.format("%06d", (int) (Math.random() * 999999));

        // Generate combined key as email + phone
        String combinedKey = email + "|" + phone;

        // Generate OTP token using JWT (store token with combined key)
        String token = jwtUtil.generateOtpToken(combinedKey, otp);

        // Store OTP with combined key (email|phone)
        otpTokenStorage.put(combinedKey, token);

        return otp;
    }

    public boolean validateOtp(String emailOrPhone, String otp) {
        System.out.println("Validating OTP for: " + emailOrPhone);
        System.out.println("Entered OTP: " + otp);

        // Fetch user either from DB or temporary storage
        User user = userService.findByUserName(emailOrPhone).orElse(null);

        if (user == null) {
            user = UserObjectUtil.getUser(emailOrPhone);
            if (user == null) {
                throw new RuntimeException("User not found for OTP validation.");
            }
        }

        String email = user.getEmail();
        String phone = user.getPhoneNum();

        // Combined key for email and phone
        String combinedKey = email + "|" + phone;

        // Check if OTP token exists for the combined key
        if (!otpTokenStorage.containsKey(combinedKey)) {
            return false; // OTP not found or expired
        }

        // Get the OTP token from the storage using combined key
        String token = otpTokenStorage.get(combinedKey);

        try {
            boolean isValid = jwtUtil.validateOtpToken(token, otp);
            if (isValid) {
                otpTokenStorage.remove(combinedKey); // Remove after successful validation
            }
            return isValid;
        } catch (Exception e) {
            otpTokenStorage.remove(combinedKey);
            return false;
        }
    }

    public String getEmailOrPhoneFromOtp(String otp) {
        String userName = otpTokenStorage.entrySet().stream().filter(entry -> {
            String token = entry.getValue();
            return jwtUtil.extractOtp(token).equals(otp);
        }).map(Map.Entry::getKey).findFirst().orElse(null);
        System.out.println("userNameFromOTP: " + userName);
        return userName;
    }
}

package com.medgenome.linc.login.config;

import org.springframework.stereotype.Component;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OtpUtil {

    private final JwtUtil jwtUtil;
    private final Map<String, String> otpTokenStorage = new ConcurrentHashMap<>();

    public OtpUtil(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public String generateOtp(String emailOrPhone) {
        String otp = String.format("%06d", (int) (Math.random() * 999999));
        String token = jwtUtil.generateOtpToken(emailOrPhone, otp);
        otpTokenStorage.put(emailOrPhone, token);
        return otp;
    }

    public boolean validateOtp(String emailOrPhone, String otp) {
        if (!otpTokenStorage.containsKey(emailOrPhone)) {
            return false; // OTP not found or expired
        }
        String token = otpTokenStorage.get(emailOrPhone);

        try {
            boolean isValid = jwtUtil.validateOtpToken(token, otp);
            if (isValid) {
                otpTokenStorage.remove(emailOrPhone); // Remove after successful validation
            }
            return isValid;
        } catch (Exception e) {
            otpTokenStorage.remove(emailOrPhone);
            return false;
        }
    }


    public String getEmailOrPhoneFromOtp(String otp) {
        String userName =  otpTokenStorage.entrySet().stream()
                .filter(entry -> {
                    String token = entry.getValue();
                    return jwtUtil.extractOtp(token).equals(otp);
                })
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
        System.out.println("userNameFromOTP: " + userName);
        return userName;
    }

}

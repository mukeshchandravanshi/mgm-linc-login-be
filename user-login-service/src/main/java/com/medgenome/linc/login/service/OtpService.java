package com.medgenome.linc.login.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class OtpService {

    private final Map<String, String> otpStorage = new ConcurrentHashMap<>();
    private final Map<String, Long> otpExpiry = new ConcurrentHashMap<>();
    private static final long OTP_EXPIRATION_TIME_MS = 5 * 60 * 1000; // 5 Minutes

    public String generateOtp(String key) {
        String otp = String.format("%06d", new Random().nextInt(999999));
        otpStorage.put(key, otp);
        otpExpiry.put(key, System.currentTimeMillis() + OTP_EXPIRATION_TIME_MS);
        log.info("Generated OTP for {}: {}", key, otp);
        return otp;
    }

    public boolean validateOtp(String key, String otp) {
        if (!otpStorage.containsKey(key) || !otp.equals(otpStorage.get(key))) {
            return false;
        }
        if (System.currentTimeMillis() > otpExpiry.get(key)) {
            otpStorage.remove(key);
            otpExpiry.remove(key);
            return false;
        }
        otpStorage.remove(key);
        otpExpiry.remove(key);
        return true;
    }
}


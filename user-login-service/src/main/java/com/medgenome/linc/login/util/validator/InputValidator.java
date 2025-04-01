package com.medgenome.linc.login.util.validator;

import com.medgenome.linc.login.model.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

@Component
public class InputValidator {

    private static final String EMAIL_REGEX = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    private static final String PHONE_REGEX = "^\\+?[0-9\\-\\s]{7,15}$";

    public static void validate(User request) {
        if (request == null) {
            throw new RuntimeException("Request body cannot be null.");
        }

        validateRequiredFields(request);
        validateEmailAndPhone(request.getEmail(), request.getPhoneNum());
        validatePasswords(request.getPassword(), request.getConfirmPassword());
    }

    private static void validateRequiredFields(User request) {
        if (!StringUtils.hasText(request.getFirstName()) ||
                !StringUtils.hasText(request.getLastName()) ||
                !StringUtils.hasText(request.getEmail()) ||
                !StringUtils.hasText(request.getPhoneNum()) ||
                !StringUtils.hasText(request.getAccountName()) ||
                !StringUtils.hasText(String.valueOf(request.getRole())) ||
                !StringUtils.hasText(request.getCountry()) ||
                !StringUtils.hasText(String.valueOf(request.getStatus())) ||
                !StringUtils.hasText(request.getPassword()) ||
                !StringUtils.hasText(request.getConfirmPassword())) {
            throw new RuntimeException("All fields are required.");
        }
    }

    private static void validateEmailAndPhone(String email, String phoneNum) {
        if (email != null && !Pattern.matches(EMAIL_REGEX, email)) {
            throw new RuntimeException("Invalid email format.");
        }

        if (phoneNum != null && !Pattern.matches(PHONE_REGEX, phoneNum)) {
            throw new RuntimeException("Invalid phone number format.");
        }
    }

    private static void validatePasswords(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new RuntimeException("Password and Confirm Password do not match.");
        }
    }

    public static String getValidEmailOrPhone(User request) {
        String emailOrPhone = (StringUtils.hasText(request.getEmail())) ? request.getEmail() : request.getPhoneNum();
        if (!StringUtils.hasText(emailOrPhone)) {
            throw new RuntimeException("Email or phone number is required.");
        }
        return emailOrPhone;
    }

    public static boolean isEmail(String input) {
        return input != null && input.contains("@");
    }
}

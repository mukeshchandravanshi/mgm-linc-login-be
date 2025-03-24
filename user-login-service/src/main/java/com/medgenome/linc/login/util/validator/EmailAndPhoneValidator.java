package com.medgenome.linc.login.util.validator;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class EmailAndPhoneValidator {

    public void validateEmailAndPhone(String email, String phoneNum) {
        String emailRegex = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        String phoneRegex = "^\\+?[0-9\\-\\s]{7,15}$";

        if (email != null && !Pattern.matches(emailRegex, email)) {
            throw new RuntimeException("Invalid email format.");
        }

        if (phoneNum != null && !Pattern.matches(phoneRegex, phoneNum)) {
            throw new RuntimeException("Invalid phone number format.");
        }
    }

}

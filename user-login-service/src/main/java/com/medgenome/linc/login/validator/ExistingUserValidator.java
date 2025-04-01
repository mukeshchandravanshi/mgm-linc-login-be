package com.medgenome.linc.login.validator;

import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.service.UserService;
import org.springframework.stereotype.Component;

@Component
public class ExistingUserValidator {
    private final UserService userService;

    public ExistingUserValidator(UserService userService) {
        this.userService = userService;
    }

    public User validateUserExists(String emailOrPhone) {
        return userService.findByUserName(emailOrPhone)
                .orElseThrow(() -> new RuntimeException("User not found with provided email or phone number."));
    }
}

package com.medgenome.linc.login.validator;

import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.service.UserService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserValidator {
    private final UserService userService;
    private User user;
    private final PasswordEncoder passwordEncoder;

    public UserValidator(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public User validateUserExists(String emailOrPhone) {
        user = userService.findByUserName(emailOrPhone)
                .orElseThrow(() -> new RuntimeException("User not found with provided email or phone number."));
        return user;
    }

    public boolean validatePassword(String password) {
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid password.Please check your password.");
        }
        return true;
    }
}

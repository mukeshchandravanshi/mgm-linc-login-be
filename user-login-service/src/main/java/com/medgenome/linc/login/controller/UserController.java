package com.medgenome.linc.login.controller;

import com.medgenome.linc.login.repository.UserRepository;
import com.medgenome.linc.login.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserRepository userRepository, UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/profile")
    public String getUserProfile(Authentication authentication) {
        return "Welcome, " + authentication.getName() + "!";
    }

}

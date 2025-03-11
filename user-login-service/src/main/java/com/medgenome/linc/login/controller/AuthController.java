package com.medgenome.linc.login.controller;


import com.medgenome.linc.login.config.JwtUtil;
import com.medgenome.linc.login.model.Role;
import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public Map<String, String> register(@RequestBody User request) {
        System.out.println("payload"+request);
        String userName = request.getEmail();
        String password = request.getPassword();

        if (userName == null || password == null) {
            throw new RuntimeException("Username and password are required.");
        }

        if (userService.findByUserName(userName).isPresent()) {
            throw new RuntimeException(userName+ " username already exists.");
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(userName) // Assuming username is email
                .phoneNum(request.getPhoneNum())
                .orgName(request.getOrgName())
                .accountName(request.getAccountName())
                .role(Role.USER)
                .country(request.getCountry())
                .password(passwordEncoder.encode(password))
                .build();

        System.out.println("encodedUser:  "+user);
        userService.registerUser(user);

        String token = jwtUtil.generateToken(userName);
        System.out.println("jwtToken: " + token);
        return Map.of("token", token,  "message", "You are successfully registered to MedGenome....");
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User request) {
        System.out.println("login payload"+request);
        String userName = request.getEmail();
        String password = request.getPassword();

        User user = userService.findByUserName(userName)
                .orElseThrow(() -> new RuntimeException("Invalid username."));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password.");
        }

        String token = jwtUtil.generateToken(userName);
        return Map.of("token", token,  "message", "Welcome to MedGenome.....");
    }
}

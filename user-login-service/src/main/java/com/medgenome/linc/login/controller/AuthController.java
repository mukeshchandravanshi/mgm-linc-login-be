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
    public Map<String, String> register(@RequestBody Map<String, String> request) {
        System.out.println("payload"+request);
        String username = request.get("username");
        String password = request.get("password");

        if (username == null || password == null) {
            throw new RuntimeException("Username and password are required.");
        }

        if (userService.findByUsername(username).isPresent()) {
            throw new RuntimeException(username+ " username already exists.");
        }

        User user = new User(username, passwordEncoder.encode(password), Role.USER);
        System.out.println("encodedUser:  "+user);
        userService.registerUser(user);

        String token = jwtUtil.generateToken(username);
        System.out.println("jwtToken: " + token);
        return Map.of("token", token,  "message", "You are successfully registered to MedGenome....");
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        User user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Invalid username."));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password.");
        }

        String token = jwtUtil.generateToken(username);
        return Map.of("token", token,  "message", "Welcome to MedGenome.....");
    }
}

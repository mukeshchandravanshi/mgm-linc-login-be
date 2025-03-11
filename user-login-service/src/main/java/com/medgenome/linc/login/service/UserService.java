package com.medgenome.linc.login.service;


import com.medgenome.linc.login.model.User;
import com.medgenome.linc.login.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String userName) {
        return userRepository.findByEmail(userName)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public Optional<User> findByUserName(String username) {
        // Check both email and phone number
        return userRepository.findByEmail(username)
                .or(() -> userRepository.findByPhoneNum(username));
    }

    public User registerUser(User user) {
        System.out.println("save user:   "+user.getUsername()+", "+user.getPassword()+","+user.getRole());
        return userRepository.save(user);
    }
}

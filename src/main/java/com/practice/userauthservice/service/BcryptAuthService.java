package com.practice.userauthservice.service;

import com.practice.userauthservice.exception.UserNotFoundException;
import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import com.practice.userauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class BcryptAuthService implements IAuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    @Override
    public User register(String email, String password, String name) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("User already exists");
        }
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(Role.USER);
        user.setName(name);
        user.setCreatedAt(new Date());
        user.setUpdatedAt(new Date());
        return userRepository.save(user);
    }

    @Override
    public boolean login(String email, String password) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            throw new UserNotFoundException("User with email " + email + " not found");
        }
        return passwordEncoder.matches(password, user.getPassword());
    }
}

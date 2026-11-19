package com.practice.userauthservice.service;

import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import com.practice.userauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OAuthLoginService implements SocialLogin {
    private final UserRepository userRepository;
    @Override
    public User findOrCreate(String provider, String providerUserId) {
        return userRepository.findByProviderAndProviderUserId(provider, providerUserId)
                .orElseGet(() -> {
                    User user = new User();
                    user.setProvider(provider);
                    user.setProviderUserId(providerUserId);
                    user.setRole(Role.USER);
                    return userRepository.save(user);
                });
    }
}

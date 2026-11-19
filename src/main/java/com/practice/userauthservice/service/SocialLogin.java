package com.practice.userauthservice.service;

import com.practice.userauthservice.model.User;

public interface SocialLogin {
    User findOrCreate(String provider, String providerUserId);
}

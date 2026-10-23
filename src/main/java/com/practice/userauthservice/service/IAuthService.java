package com.practice.userauthservice.service;

import com.practice.userauthservice.model.User;

public interface IAuthService {
    User register(String email, String password, String name);
    String login(String email, String password);
}

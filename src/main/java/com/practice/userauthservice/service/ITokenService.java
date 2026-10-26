package com.practice.userauthservice.service;

import com.practice.userauthservice.model.User;
import io.jsonwebtoken.Claims;

public interface ITokenService {
    String generateToken(User user);
    Claims validateToken(String token);
}

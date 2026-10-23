package com.practice.userauthservice.service;

import io.jsonwebtoken.Claims;

public interface ITokenService {
    String generateToken(String subject);
    Claims validateToken(String token);
}

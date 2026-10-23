package com.practice.userauthservice.service;

public interface ITokenService {
    String generateToken(String subject);
}

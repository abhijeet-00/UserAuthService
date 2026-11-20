package com.practice.userauthservice.controller;

import com.practice.userauthservice.service.ITokenService;
import com.practice.userauthservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwtKeyController {
    private final JwtService jwtService;
    // Any service can read this address and check our tokens. No call to us per request.
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return Map.of("keys", List.of(jwtService.publicKeyAsJwk()));
    }
}

package com.practice.userauthservice.service;

import com.practice.userauthservice.model.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService implements ITokenService {
    private final SecretKey secretKey;
    private final long jwtExpiration;

    public JwtService(@Value("${jwt.secret}") String secretKey, @Value("${jwt.expiration}") long jwtExpiration) {
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.jwtExpiration = jwtExpiration;
    }

    @Override
    public String generateToken(String subject) {
        return Jwts.builder().subject(subject).claim("role", Role.USER)
                .signWith(secretKey)
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration * 1000))
                .compact();
    }

    @Override
    public Claims validateToken(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
    }
}

package com.practice.userauthservice.service;

import com.practice.userauthservice.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Service
public class JwtService implements ITokenService {
    private final KeyPair keyPair;
    private final long jwtExpiration;
    private final String audience;
    private final String keyId;

    public JwtService(@Value("${jwt.expiration}") long jwtExpiration,
                      @Value("${jwt.audience}") String audience) throws NoSuchAlgorithmException {
        this.jwtExpiration = jwtExpiration;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        this.keyPair = generator.generateKeyPair();
        this.audience = audience;
        this.keyId = UUID.randomUUID().toString();
    }

    @Override
    public String generateToken(User user) {
        return Jwts.builder().subject(user.getEmail()).claim("role", user.getRole().name())
                .signWith(keyPair.getPrivate())
                .audience().add(audience).and()
                .issuedAt(new Date())
                .issuer("User Auth Service")
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration * 1000))
                .compact();
    }

    @Override
    public Claims validateToken(String token) {
        return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload();
    }

    // The public key in the standard JSON form (a JWK). Anyone may read it.
    public Map<String, Object> publicKeyAsJwk() {
        RSAPublicKey key = (RSAPublicKey) keyPair.getPublic();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", keyId,
                "n", encoder.encodeToString(unsignedBytes(key.getModulus())),
                "e", encoder.encodeToString(unsignedBytes(key.getPublicExponent())));
    }

    private static byte[] unsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }
}

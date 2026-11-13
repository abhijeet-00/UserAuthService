package com.practice.userauthservice.service;

import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwtServiceTests {
    private static final String EMAIL = "xyz@gmail.com";
    private static final String SECRET = "test-secret-key-that-is-at-least-32-bytes-long";
    private static final String OTHER_SECRET = "other-secret-key-that-is-at-least-32-bytes-long";
    private static final long EXPIRATION_SECONDS = 3600L;

    private final JwtService jwtService = new JwtService(SECRET, EXPIRATION_SECONDS);

    @Test
    void generateToken_returnsThreePartJwt() {
        String token = jwtService.generateToken(buildUser(Role.USER));

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void generateToken_setsEmailAsSubject() {
        String token = jwtService.generateToken(buildUser(Role.USER));

        Claims claims = jwtService.validateToken(token);

        assertEquals(EMAIL, claims.getSubject());
    }

    @ParameterizedTest
    @EnumSource(Role.class)
    void generateToken_includesRoleClaim(Role role) {
        String token = jwtService.generateToken(buildUser(role));

        Claims claims = jwtService.validateToken(token);

        assertEquals(role.name(), claims.get("role", String.class));
    }

    @Test
    void generateToken_setsIssuedAtAndExpiration() {
        long before = System.currentTimeMillis();
        String token = jwtService.generateToken(buildUser(Role.USER));
        long after = System.currentTimeMillis();

        Claims claims = jwtService.validateToken(token);

        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());

        long issuedAt = claims.getIssuedAt().getTime();
        assertTrue(issuedAt >= before - 1000 && issuedAt <= after + 1000,
                "issuedAt should be close to the time the token was generated");

        long expectedValidityMillis = EXPIRATION_SECONDS * 1000;
        long actualValidityMillis = claims.getExpiration().getTime() - issuedAt;
        assertTrue(Math.abs(actualValidityMillis - expectedValidityMillis) <= 1000,
                "expiration should be issuedAt plus the configured expiration");
    }

    @Test
    void validateToken_validToken_returnsClaims() {
        String token = jwtService.generateToken(buildUser(Role.ADMIN));

        Claims claims = jwtService.validateToken(token);

        assertEquals(EMAIL, claims.getSubject());
        assertEquals(Role.ADMIN.name(), claims.get("role", String.class));
        assertTrue(claims.getExpiration().getTime() > System.currentTimeMillis());
    }

    @Test
    void validateToken_expiredToken_throwsExpiredJwtException() {
        JwtService expiredTokenService = new JwtService(SECRET, -10L);
        String token = expiredTokenService.generateToken(buildUser(Role.USER));

        assertThrows(ExpiredJwtException.class, () -> jwtService.validateToken(token));
    }

    @Test
    void validateToken_tokenSignedWithDifferentSecret_throwsSignatureException() {
        JwtService otherService = new JwtService(OTHER_SECRET, EXPIRATION_SECONDS);
        String token = otherService.generateToken(buildUser(Role.USER));

        assertThrows(SignatureException.class, () -> jwtService.validateToken(token));
    }

    @Test
    void validateToken_tamperedSignature_throwsSignatureException() {
        String token = jwtService.generateToken(buildUser(Role.USER));
        String[] parts = token.split("\\.");
        char firstChar = parts[2].charAt(0);
        char tamperedChar = firstChar == 'A' ? 'B' : 'A';
        parts[2] = tamperedChar + parts[2].substring(1);
        String tamperedToken = String.join(".", parts);

        assertThrows(SignatureException.class, () -> jwtService.validateToken(tamperedToken));
    }

    @Test
    void validateToken_malformedToken_throwsMalformedJwtException() {
        assertThrows(MalformedJwtException.class, () -> jwtService.validateToken("not-a-jwt"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateToken_nullOrEmptyToken_throwsIllegalArgumentException(String token) {
        assertThrows(IllegalArgumentException.class, () -> jwtService.validateToken(token));
    }

    private User buildUser(Role role) {
        User user = new User();
        user.setEmail(EMAIL);
        user.setName("Abhijeet");
        user.setPassword("encoded_password");
        user.setRole(role);
        return user;
    }
}

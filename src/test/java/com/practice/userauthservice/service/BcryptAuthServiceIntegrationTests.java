package com.practice.userauthservice.service;

import com.practice.userauthservice.exception.UserNotFoundException;
import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import com.practice.userauthservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class BcryptAuthServiceIntegrationTests {
    private static final String NAME = "Abhijeet";
    private static final String PASSWORD = "Abhi@2001";

    @Autowired
    private BcryptAuthService bcryptAuthService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void register_newEmail_persistsUserWithEncodedPasswordAndUserRole() {
        String email = uniqueEmail();

        User result = bcryptAuthService.register(email, PASSWORD, NAME);

        entityManager.flush();
        entityManager.clear();
        User savedUser = userRepository.findById(result.getId()).orElseThrow();

        assertAll(
                () -> assertNotNull(savedUser.getId()),
                () -> assertEquals(NAME, savedUser.getName()),
                () -> assertEquals(email, savedUser.getEmail()),
                () -> assertEquals(Role.USER, savedUser.getRole()),
                () -> assertNotEquals(PASSWORD, savedUser.getPassword()),
                () -> assertTrue(passwordEncoder.matches(PASSWORD, savedUser.getPassword())),
                () -> assertNotNull(savedUser.getCreatedAt()),
                () -> assertNotNull(savedUser.getUpdatedAt())
        );
    }

    @Test
    void register_existingEmail_throwsIllegalArgumentException() {
        String email = uniqueEmail();
        userRepository.saveAndFlush(buildUser(email));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> bcryptAuthService.register(email, PASSWORD, NAME));

        assertEquals("User already exists", exception.getMessage());
        entityManager.flush();
        entityManager.clear();
        long usersWithEmail = userRepository.findAll().stream()
                .filter(user -> email.equals(user.getEmail()))
                .count();
        assertEquals(1, usersWithEmail);
    }

    @Test
    void login_validCredentials_returnsValidJwt() {
        String email = uniqueEmail();
        bcryptAuthService.register(email, PASSWORD, NAME);
        entityManager.flush();
        entityManager.clear();

        String token = bcryptAuthService.login(email, PASSWORD);

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);

        Claims claims = jwtService.validateToken(token);
        assertEquals(email, claims.getSubject());
        assertEquals(Role.USER.name(), claims.get("role", String.class));
        assertTrue(claims.getExpiration().getTime() > System.currentTimeMillis());
    }

    @Test
    void login_userNotFound_throwsUserNotFoundException() {
        String email = uniqueEmail();

        UserNotFoundException exception = assertThrows(UserNotFoundException.class,
                () -> bcryptAuthService.login(email, PASSWORD));

        assertEquals("User with email " + email + " not found", exception.getMessage());
    }

    @Test
    void login_wrongPassword_returnsNull() {
        String email = uniqueEmail();
        bcryptAuthService.register(email, PASSWORD, NAME);
        entityManager.flush();
        entityManager.clear();

        String token = bcryptAuthService.login(email, "wrong-password");

        assertNull(token);
    }

    private String uniqueEmail() {
        return "it-" + UUID.randomUUID() + "@gmail.com";
    }

    private User buildUser(String email) {
        User user = new User();
        user.setEmail(email);
        user.setName(NAME);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setRole(Role.USER);
        user.setCreatedAt(new Date());
        user.setUpdatedAt(new Date());
        return user;
    }
}

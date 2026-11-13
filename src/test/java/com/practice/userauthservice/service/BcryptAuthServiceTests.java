package com.practice.userauthservice.service;

import com.practice.userauthservice.exception.UserNotFoundException;
import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import com.practice.userauthservice.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class BcryptAuthServiceTests {
    private static final String EMAIL = "xyz@gmail.com";
    private static final String NAME = "Abhijeet";
    private static final String PASSWORD = "Abhi@2001";
    private static final String ENCODED_PASSWORD = "encoded_password";

    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ITokenService tokenService;
    @InjectMocks
    private BcryptAuthService bcryptAuthService;

    @Test
    void register_newEmail_savesUserWithEncodedPasswordAndUserRole() {
        when(passwordEncoder.encode(PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(answer -> answer.getArgument(0));

        long before = System.currentTimeMillis();
        User result = bcryptAuthService.register(EMAIL, PASSWORD, NAME);
        long after = System.currentTimeMillis();

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertAll(
                () -> assertEquals(NAME, result.getName()),
                () -> assertEquals(EMAIL, result.getEmail()),
                () -> assertEquals(ENCODED_PASSWORD, result.getPassword()),
                () -> assertEquals(Role.USER, savedUser.getRole()),
                () -> assertNotEquals(PASSWORD, savedUser.getPassword()),
                () -> assertNotNull(savedUser.getCreatedAt()),
                () -> assertNotNull(savedUser.getUpdatedAt()),
                () -> assertTrue(savedUser.getCreatedAt().getTime() >= before
                        && savedUser.getCreatedAt().getTime() <= after),
                () -> assertTrue(savedUser.getUpdatedAt().getTime() >= before
                        && savedUser.getUpdatedAt().getTime() <= after)
        );
        verify(passwordEncoder).encode(PASSWORD);
        verify(userRepository).existsByEmail(EMAIL);
    }

    @Test
    void register_existingEmail_throwsIllegalArgumentException() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> bcryptAuthService.register(EMAIL, PASSWORD, NAME));

        assertEquals("User already exists", exception.getMessage());
        verifyNoInteractions(passwordEncoder);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_validCredentials_returnsTokenFromTokenService() {
        User user = buildUser();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(tokenService.generateToken(user)).thenReturn("jwt-token");

        String token = bcryptAuthService.login(EMAIL, PASSWORD);

        assertEquals("jwt-token", token);
        verify(userRepository).findByEmail(EMAIL);
        verify(passwordEncoder).matches(PASSWORD, ENCODED_PASSWORD);
        verify(tokenService).generateToken(user);
    }

    @Test
    void login_userNotFound_throwsUserNotFoundException() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        UserNotFoundException exception = assertThrows(UserNotFoundException.class,
                () -> bcryptAuthService.login(EMAIL, PASSWORD));

        assertEquals("User with email " + EMAIL + " not found", exception.getMessage());
        verifyNoInteractions(passwordEncoder, tokenService);
    }

    @Test
    void login_wrongPassword_returnsNull() {
        User user = buildUser();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

        String token = bcryptAuthService.login(EMAIL, PASSWORD);

        assertNull(token);
        verify(tokenService, never()).generateToken(any(User.class));
    }

    private User buildUser() {
        User user = new User();
        user.setEmail(EMAIL);
        user.setName(NAME);
        user.setPassword(ENCODED_PASSWORD);
        user.setRole(Role.USER);
        return user;
    }
}

package com.practice.userauthservice.controller;

import com.practice.userauthservice.configuration.SecurityConfig;
import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import com.practice.userauthservice.repository.UserRepository;
import com.practice.userauthservice.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
@EnableWebSecurity
public class UserControllerTests {
    private static final String EMAIL = "xyz@gmail.com";

    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private UserRepository userRepository;
    @MockitoBean
    private JwtService jwtService;

    @Test
    void getUser_authenticatedUser_returnsUserDto() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setEmail(EMAIL);
        user.setName("Abhijeet");
        user.setPassword("encoded_password");
        user.setRole(Role.USER);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        mockMvc.perform(get("/users/me").with(user(EMAIL)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.name").value("Abhijeet"))
                .andExpect(jsonPath("$.role").value(Role.USER.name()));

        verify(userRepository).findByEmail(EMAIL);
    }

    @Test
    void getUser_userNotFound_returnsEmptyUserDto() throws Exception {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        mockMvc.perform(get("/users/me").with(user(EMAIL)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").isEmpty())
                .andExpect(jsonPath("$.email").isEmpty())
                .andExpect(jsonPath("$.name").isEmpty())
                .andExpect(jsonPath("$.role").isEmpty());
    }

    @Test
    void getUser_unauthenticated_returnsUnauthorized() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized());
    }
}

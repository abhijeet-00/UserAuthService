package com.practice.userauthservice.controller;

import com.practice.userauthservice.configuration.SecurityConfig;
import com.practice.userauthservice.model.Role;
import com.practice.userauthservice.model.User;
import com.practice.userauthservice.service.IAuthService;
import com.practice.userauthservice.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
@EnableWebSecurity
public class AuthControllerTests {
    private static final String EMAIL = "xyz@gmail.com";
    private static final String PASSWORD = "Abhi@2001";
    private static final String NAME = "Abhijeet";

    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private IAuthService authService;
    @MockitoBean
    private JwtService jwtService;

    @Test
    void register_validRequest_returnsCreatedUserDto() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setEmail(EMAIL);
        user.setName(NAME);
        user.setRole(Role.USER);
        when(authService.register(EMAIL, PASSWORD, NAME)).thenReturn(user);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"xyz@gmail.com","password":"Abhi@2001","name":"Abhijeet"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.name").value(NAME))
                .andExpect(jsonPath("$.role").value(Role.USER.name()))
                .andExpect(jsonPath("$.password").doesNotExist());

        verify(authService).register(EMAIL, PASSWORD, NAME);
    }

    @Test
    void login_invalidCredentials_returnsUnauthorized() throws Exception {
        when(authService.login(EMAIL, "wrong-password")).thenReturn(null);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"xyz@gmail.com","password":"wrong-password"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));

        verify(authService).login(EMAIL, "wrong-password");
    }
}

package com.practice.userauthservice.security;

import com.practice.userauthservice.model.User;
import com.practice.userauthservice.service.ITokenService;
import com.practice.userauthservice.service.SocialLogin;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class SocialLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final ITokenService tokenService;
    private final SocialLogin socialLogin;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken login = (OAuth2AuthenticationToken) authentication;
        // "github" or "google", the name we gave the login in application.properties.
        String provider = login.getAuthorizedClientRegistrationId();
        // The person's id at that provider: GitHub's id, or Google's sub.
        String providerUserId = login.getName();

        User user = socialLogin.findOrCreate(provider, providerUserId);

        // For the class we return the token as JSON. A real web page needs a safer hand-over.
        response.setContentType("application/json");
        response.getWriter().write("{\"token\":\"" + tokenService.generateToken(user) + "\"}");
    }
}

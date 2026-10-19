package com.practice.userauthservice.controller;

import com.practice.userauthservice.model.User;
import com.practice.userauthservice.model.dto.AuthRequest;
import com.practice.userauthservice.model.dto.UserDto;
import com.practice.userauthservice.service.IAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final IAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody AuthRequest authRequest) {
        User user = authService.register(authRequest.getEmail(), authRequest.getPassword(), authRequest.getName());
        return new ResponseEntity<>(from(user), HttpStatus.CREATED);
    }
    private UserDto from(User user) {
        UserDto userDto = new UserDto();
        userDto.setUserId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setName(user.getName());
        return userDto;
    }
}

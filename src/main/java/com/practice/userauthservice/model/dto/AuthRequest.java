package com.practice.userauthservice.model.dto;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

@Getter
@Setter
public class AuthRequest {
    private String name;
    @NonNull
    private String email;
    @NonNull
    private String password;
}

package com.practice.userauthservice.model.dto;

import com.practice.userauthservice.model.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDto {
    private Long userId;
    private String name;
    private String email;
    private Role role;
}

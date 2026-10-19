package com.practice.userauthservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class User extends BaseEntity {
    private String name;
    @Column(unique = true)
    private String email;
    private String password;
    private Role role;
}

package com.nymblsystems.auth.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
public @Data class ClientUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String email;
    private String password;

    public ClientUser() {

    }

    public ClientUser(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
}

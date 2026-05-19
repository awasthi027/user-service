package com.userservice.model;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "user_id", updatable = false, nullable = false)
    private String userId = UUID.randomUUID().toString();

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;   // BCrypt hash

    @Column(nullable = false)
    private String role = "user";

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    // ── JPA requires no-arg constructor ──────────────────────────────────
    public User() {}

    public User(String userId, String name, String email, String password, String role) {
        this.userId   = userId;
        this.name     = name;
        this.email    = email;
        this.password = password;
        this.role     = role;
    }

    // Getters
    public String  getUserId()   { return userId;    }
    public String  getName()     { return name;      }
    public String  getEmail()    { return email;     }
    public String  getPassword() { return password;  }
    public String  getRole()     { return role;      }
    public Instant getCreatedAt(){ return createdAt; }

    // Setters
    public void setUserId(String userId)     { this.userId   = userId;   }
    public void setName(String name)         { this.name     = name;     }
    public void setEmail(String email)       { this.email    = email;    }
    public void setPassword(String password) { this.password = password; }
    public void setRole(String role)         { this.role     = role;     }
}
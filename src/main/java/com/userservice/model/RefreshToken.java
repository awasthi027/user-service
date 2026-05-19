package com.userservice.model;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private String id = UUID.randomUUID().toString();

    /** The raw JWT refresh-token string (used as the lookup key). */
    @Column(nullable = false, length = 2048)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    // ── JPA no-arg constructor ────────────────────────────────────────────
    public RefreshToken() {}

    public RefreshToken(String token, User user, Instant expiryDate) {
        this.token      = token;
        this.user       = user;
        this.expiryDate = expiryDate;
    }

    // Getters / Setters
    public String  getId()         { return id;         }
    public String  getToken()      { return token;      }
    public User    getUser()       { return user;       }
    public Instant getExpiryDate() { return expiryDate; }
    public boolean isRevoked()     { return revoked;    }

    public void setToken(String token)           { this.token      = token;      }
    public void setUser(User user)               { this.user       = user;       }
    public void setExpiryDate(Instant expiryDate){ this.expiryDate = expiryDate; }
    public void setRevoked(boolean revoked)      { this.revoked    = revoked;    }
}


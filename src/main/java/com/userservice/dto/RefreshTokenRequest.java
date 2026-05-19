package com.userservice.dto;

import jakarta.validation.constraints.NotBlank;

public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;

    // Getters & Setters
    public String getRefreshToken()                  { return refreshToken;        }
    public void   setRefreshToken(String refreshToken){ this.refreshToken = refreshToken; }
}


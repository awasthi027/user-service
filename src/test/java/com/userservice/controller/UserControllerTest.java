package com.userservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.userservice.config.SecurityConfig;
import com.userservice.dto.LoginRequest;
import com.userservice.dto.RefreshTokenRequest;
import com.userservice.dto.RegisterRequest;
import com.userservice.model.User;
import com.userservice.service.UserService;
import com.userservice.service.UserService.TokenPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Slice tests for {@link UserController} using MockMvc.
 * The Spring Security auto-config is active but all endpoints are
 * permitted (see SecurityConfig), so no auth header is required.
 */
@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
class UserControllerTest {

    @Autowired MockMvc       mockMvc;
    @Autowired ObjectMapper  objectMapper;
    @MockBean  UserService   userService;

    private User      sampleUser;
    private TokenPair sampleTokenPair;

    @BeforeEach
    void setUp() {
        sampleUser = new User();
        sampleUser.setUserId(UUID.randomUUID().toString());
        sampleUser.setName("John Doe");
        sampleUser.setEmail("john@example.com");
        sampleUser.setPassword("$2a$hashed");
        sampleUser.setRole("user");

        sampleTokenPair = new TokenPair(
                "mock-access-token",
                "mock-refresh-token",
                900L,
                sampleUser);
    }

    // ── Health ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/users/health → 200")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/users/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.message").value("User Service is UP"));
    }

    // ── Register ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /register – success → 201 with userId")
    void register_success_returns201() throws Exception {
        when(userService.findByEmail("john@example.com")).thenReturn(Optional.empty());
        when(userService.register(anyString(), anyString(), anyString()))
                .thenReturn(sampleUser);

        RegisterRequest req = new RegisterRequest();
        req.setName("John Doe");
        req.setEmail("john@example.com");
        req.setPassword("secret123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value(201))
                .andExpect(jsonPath("$.data.email").value("john@example.com"));
    }

    @Test
    @DisplayName("POST /register – duplicate email → 409")
    void register_duplicateEmail_returns409() throws Exception {
        when(userService.findByEmail("john@example.com")).thenReturn(Optional.of(sampleUser));

        RegisterRequest req = new RegisterRequest();
        req.setName("John Doe");
        req.setEmail("john@example.com");
        req.setPassword("secret123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    @DisplayName("POST /register – missing name → 400")
    void register_missingName_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("john@example.com");
        req.setPassword("secret123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /register – invalid email format → 400")
    void register_invalidEmail_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setName("John");
        req.setEmail("not-an-email");
        req.setPassword("secret123");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /register – password too short → 400")
    void register_shortPassword_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setName("John");
        req.setEmail("john@example.com");
        req.setPassword("short");

        mockMvc.perform(post("/api/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // ── Login ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /login – valid credentials → 200 with Bearer tokens")
    void login_validCredentials_returns200WithTokens() throws Exception {
        when(userService.login("john@example.com", "secret123"))
                .thenReturn(Optional.of(sampleTokenPair));

        LoginRequest req = new LoginRequest();
        req.setEmail("john@example.com");
        req.setPassword("secret123");

        mockMvc.perform(post("/api/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.accessToken").value("mock-access-token"))
                .andExpect(jsonPath("$.data.refreshToken").value("mock-refresh-token"))
                .andExpect(jsonPath("$.data.expiresIn").value(900))
                .andExpect(jsonPath("$.data.role").value("user"));
    }

    @Test
    @DisplayName("POST /login – bad credentials → 401")
    void login_badCredentials_returns401() throws Exception {
        when(userService.login(anyString(), anyString())).thenReturn(Optional.empty());

        LoginRequest req = new LoginRequest();
        req.setEmail("john@example.com");
        req.setPassword("wrongpassword");

        mockMvc.perform(post("/api/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("POST /login – missing email → 400")
    void login_missingEmail_returns400() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setPassword("secret123");

        mockMvc.perform(post("/api/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // ── Refresh Token ─────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /refresh – valid token → 200 with new tokens")
    void refresh_validToken_returns200() throws Exception {
        when(userService.refresh("mock-refresh-token"))
                .thenReturn(Optional.of(sampleTokenPair));

        RefreshTokenRequest req = new RefreshTokenRequest();
        req.setRefreshToken("mock-refresh-token");

        mockMvc.perform(post("/api/users/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.data.refreshToken").isNotEmpty());
    }

    @Test
    @DisplayName("POST /refresh – invalid/expired token → 401")
    void refresh_invalidToken_returns401() throws Exception {
        when(userService.refresh(anyString())).thenReturn(Optional.empty());

        RefreshTokenRequest req = new RefreshTokenRequest();
        req.setRefreshToken("expired-or-revoked-token");

        mockMvc.perform(post("/api/users/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("POST /refresh – missing refreshToken field → 400")
    void refresh_missingToken_returns400() throws Exception {
        mockMvc.perform(post("/api/users/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // ── Get User by ID ────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /{id} – existing user → 200")
    void getUserById_exists_returns200() throws Exception {
        when(userService.findById(sampleUser.getUserId())).thenReturn(Optional.of(sampleUser));

        mockMvc.perform(get("/api/users/{id}", sampleUser.getUserId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("john@example.com"));
    }

    @Test
    @DisplayName("GET /{id} – unknown id → 404")
    void getUserById_notFound_returns404() throws Exception {
        when(userService.findById(anyString())).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/users/unknown-id"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    // ── Get All Users ─────────────────────────────────────────────────────

    @Test
    @DisplayName("GET / – returns list of users")
    void getAllUsers_returnsList() throws Exception {
        when(userService.getAllUsers()).thenReturn(List.of(sampleUser));

        mockMvc.perform(get("/api/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(200))
                .andExpect(jsonPath("$.data[0].email").value("john@example.com"));
    }
}


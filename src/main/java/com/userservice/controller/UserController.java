package com.userservice.controller;

import com.userservice.dto.ApiResponse;
import com.userservice.dto.LoginRequest;
import com.userservice.dto.RefreshTokenRequest;
import com.userservice.dto.RegisterRequest;
import com.userservice.service.JwtService;
import com.userservice.service.UserService;
import com.userservice.service.UserService.TokenPair;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;

    public UserController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    // ── Health Check ──────────────────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<ApiResponse> health() {
        return ResponseEntity.ok(new ApiResponse(200, "User Service is UP", null));
    }

    // ── Register ──────────────────────────────────────────────────────────
    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody RegisterRequest req) {

        if (userService.findByEmail(req.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    new ApiResponse(409, "Email already registered.", null));
        }

        var newUser = userService.register(req.getName(), req.getEmail(), req.getPassword());

        return ResponseEntity.status(HttpStatus.CREATED).body(
                new ApiResponse(201, "User registered successfully", Map.of(
                        "userId", newUser.getUserId(),
                        "name",   newUser.getName(),
                        "email",  newUser.getEmail()
                )));
    }

    // ── Login ─────────────────────────────────────────────────────────────
    @PostMapping("/login")
    public ResponseEntity<ApiResponse> login(@Valid @RequestBody LoginRequest req) {

        Optional<TokenPair> result = userService.login(req.getEmail(), req.getPassword());

        if (result.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(401, "Invalid email or password.", null));
        }

        TokenPair tp = result.get();
        return ResponseEntity.ok(new ApiResponse(200, "Login successful", Map.of(
                "tokenType",      "Bearer",
                "accessToken",    tp.accessToken(),
                "refreshToken",   tp.refreshToken(),
                "expiresIn",      tp.expiresInSeconds(),
                "userId",         tp.user().getUserId(),
                "email",          tp.user().getEmail(),
                "role",           tp.user().getRole()
        )));
    }

    // ── Refresh Token ─────────────────────────────────────────────────────
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse> refresh(@Valid @RequestBody RefreshTokenRequest req) {

        Optional<TokenPair> result = userService.refresh(req.getRefreshToken());

        if (result.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(401, "Refresh token is invalid, expired or revoked.", null));
        }

        TokenPair tp = result.get();
        return ResponseEntity.ok(new ApiResponse(200, "Token refreshed", Map.of(
                "tokenType",    "Bearer",
                "accessToken",  tp.accessToken(),
                "refreshToken", tp.refreshToken(),
                "expiresIn",    tp.expiresInSeconds()
        )));
    }

    // ── Get User by ID ────────────────────────────────────────────────────
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse> getUserById(@PathVariable String id) {

        return userService.findById(id)
                .map(u -> ResponseEntity.ok(new ApiResponse(200, "User found", Map.of(
                        "userId", u.getUserId(),
                        "name",   u.getName(),
                        "email",  u.getEmail(),
                        "role",   u.getRole()
                ))))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse(404, "User not found.", null)));
    }

    // ── Get All Users ─────────────────────────────────────────────────────
    @GetMapping
    public ResponseEntity<ApiResponse> getAllUsers() {
        return ResponseEntity.ok(new ApiResponse(200, "Users fetched",
                userService.getAllUsers().stream()
                        .map(u -> Map.of(
                                "userId", u.getUserId(),
                                "name",   u.getName(),
                                "email",  u.getEmail()
                        ))
                        .toList()));
    }

    // ── Logout ────────────────────────────────────────────────────────────
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(401, "Missing or invalid Authorization header.", null));
        }

        String token = authHeader.substring(7);

        if (!jwtService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(401, "Invalid or expired token.", null));
        }

        String userId = jwtService.extractUserId(token);

        return userService.findById(userId)
                .map(user -> {
                    userService.logout(user);
                    return ResponseEntity.ok(new ApiResponse(200, "Logged out successfully", null));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse(404, "User not found.", null)));
    }

    // ── Delete User ───────────────────────────────────────────────────────
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse> deleteUser(
            @PathVariable String id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(401, "Missing or invalid Authorization header.", null));
        }

        String token = authHeader.substring(7);

        if (!jwtService.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new ApiResponse(401, "Invalid or expired token.", null));
        }

        String requestingUserId = jwtService.extractUserId(token);

        // Users can only delete their own account
        if (!requestingUserId.equals(id)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                    new ApiResponse(403, "You can only delete your own account.", null));
        }

        return userService.findById(id)
                .map(user -> {
                    userService.deleteUser(id);
                    return ResponseEntity.ok(new ApiResponse(200, "User deleted successfully", null));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse(404, "User not found.", null)));
    }
}
package com.userservice.service;

import com.userservice.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Pure unit tests for {@link JwtService} – no Spring context needed.
 */
class JwtServiceTest {

    // Base64 of "test-secret-for-unit-testing-only-must-be-256-bits"
    private static final String SECRET =
            "dGVzdC1zZWNyZXQtZm9yLXVuaXQtdGVzdGluZy1vbmx5LW11c3QtYmUtMjU2LWJpdHM=";

    private JwtService jwtService;
    private User       testUser;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(SECRET, 900_000L, 604_800_000L,
                "user-service", "api-gateway");

        testUser = new User();
        testUser.setUserId("user-123");
        testUser.setEmail("john@example.com");
        testUser.setRole("user");
    }

    // ── Access Token ──────────────────────────────────────────────────────

    @Test
    @DisplayName("generateAccessToken – returns a non-blank JWT")
    void generateAccessToken_returnsToken() {
        String token = jwtService.generateAccessToken(testUser);
        assertThat(token).isNotBlank();
        assertThat(token.split("\\.")).hasSize(3); // header.payload.signature
    }

    @Test
    @DisplayName("generateAccessToken – contains expected claims")
    void generateAccessToken_claimsAreCorrect() {
        String  token  = jwtService.generateAccessToken(testUser);
        Claims  claims = jwtService.validateAndGetClaims(token);

        assertThat(claims.getSubject()).isEqualTo("user-123");
        assertThat(claims.get("email", String.class)).isEqualTo("john@example.com");
        assertThat(claims.get("role",  String.class)).isEqualTo("user");
        assertThat(claims.getIssuer()).isEqualTo("user-service");
        assertThat(claims.getAudience()).contains("api-gateway");
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    @DisplayName("isTokenValid – returns true for a fresh access token")
    void isTokenValid_freshToken_returnsTrue() {
        String token = jwtService.generateAccessToken(testUser);
        assertThat(jwtService.isTokenValid(token)).isTrue();
    }

    @Test
    @DisplayName("isTokenValid – returns false for a tampered token")
    void isTokenValid_tamperedToken_returnsFalse() {
        String token   = jwtService.generateAccessToken(testUser);
        String tampered = token + "tampered";
        assertThat(jwtService.isTokenValid(tampered)).isFalse();
    }

    @Test
    @DisplayName("isTokenValid – returns false for an expired token")
    void isTokenValid_expiredToken_returnsFalse() {
        // Create a service instance with –1 ms expiry → immediately expired
        JwtService shortLived = new JwtService(SECRET, -1L, -1L,
                "user-service", "api-gateway");
        String expiredToken = shortLived.generateAccessToken(testUser);
        assertThat(jwtService.isTokenValid(expiredToken)).isFalse();
    }

    @Test
    @DisplayName("validateAndGetClaims – throws JwtException for invalid token")
    void validateAndGetClaims_invalidToken_throwsException() {
        assertThatThrownBy(() -> jwtService.validateAndGetClaims("not.a.jwt"))
                .isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("extractUserId – returns correct subject")
    void extractUserId_returnsSubject() {
        String token = jwtService.generateAccessToken(testUser);
        assertThat(jwtService.extractUserId(token)).isEqualTo("user-123");
    }

    // ── Refresh Token ─────────────────────────────────────────────────────

    @Test
    @DisplayName("generateRefreshToken – returns a valid JWT")
    void generateRefreshToken_returnsToken() {
        String token = jwtService.generateRefreshToken(testUser);
        assertThat(token).isNotBlank();
        assertThat(jwtService.isTokenValid(token)).isTrue();
    }

    @Test
    @DisplayName("generateRefreshToken – sub equals userId")
    void generateRefreshToken_subjectIsUserId() {
        String token = jwtService.generateRefreshToken(testUser);
        assertThat(jwtService.extractUserId(token)).isEqualTo("user-123");
    }

    @Test
    @DisplayName("access token and refresh token are different")
    void accessAndRefreshTokensAreDifferent() {
        String access  = jwtService.generateAccessToken(testUser);
        String refresh = jwtService.generateRefreshToken(testUser);
        assertThat(access).isNotEqualTo(refresh);
    }
}


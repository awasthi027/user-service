package com.userservice.service;

import com.userservice.model.RefreshToken;
import com.userservice.model.User;
import com.userservice.repository.RefreshTokenRepository;
import com.userservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link UserService} – all dependencies mocked with Mockito.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final String SECRET =
            "dGVzdC1zZWNyZXQtZm9yLXVuaXQtdGVzdGluZy1vbmx5LW11c3QtYmUtMjU2LWJpdHM=";

    @Mock UserRepository         userRepository;
    @Mock RefreshTokenRepository refreshTokenRepository;

    private BCryptPasswordEncoder passwordEncoder;
    private JwtService             jwtService;
    private UserService            userService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        jwtService      = new JwtService(SECRET, 900_000L, 604_800_000L,
                "user-service", "api-gateway");
        userService     = new UserService(userRepository, refreshTokenRepository,
                passwordEncoder, jwtService);

        sampleUser = new User();
        sampleUser.setUserId(UUID.randomUUID().toString());
        sampleUser.setName("John Doe");
        sampleUser.setEmail("john@example.com");
        sampleUser.setPassword(passwordEncoder.encode("secret123"));
        sampleUser.setRole("user");
    }

    // ── Register ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("register – saves a user with BCrypt-hashed password")
    void register_savesUserWithHashedPassword() {
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        User result = userService.register("John Doe", "john@example.com", "secret123");

        assertThat(result.getName()).isEqualTo("John Doe");
        assertThat(result.getEmail()).isEqualTo("john@example.com");
        assertThat(result.getRole()).isEqualTo("user");
        // Password must be a BCrypt hash, not plain text
        assertThat(result.getPassword()).startsWith("$2a$");
        assertThat(passwordEncoder.matches("secret123", result.getPassword())).isTrue();

        verify(userRepository, times(1)).save(any(User.class));
    }

    // ── Login ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("login – returns TokenPair for valid credentials")
    void login_validCredentials_returnsTokenPair() {
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(sampleUser));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));

        Optional<UserService.TokenPair> result =
                userService.login("john@example.com", "secret123");

        assertThat(result).isPresent();
        assertThat(result.get().accessToken()).isNotBlank();
        assertThat(result.get().refreshToken()).isNotBlank();
        assertThat(result.get().expiresInSeconds()).isEqualTo(900L);
        assertThat(result.get().user().getEmail()).isEqualTo("john@example.com");
    }

    @Test
    @DisplayName("login – returns empty for unknown email")
    void login_unknownEmail_returnsEmpty() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThat(userService.login("ghost@example.com", "any")).isEmpty();
    }

    @Test
    @DisplayName("login – returns empty for wrong password")
    void login_wrongPassword_returnsEmpty() {
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(sampleUser));

        assertThat(userService.login("john@example.com", "wrongpassword")).isEmpty();
    }

    @Test
    @DisplayName("login – revokes old refresh tokens before issuing new ones")
    void login_revokesOldRefreshTokens() {
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(sampleUser));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        userService.login("john@example.com", "secret123");

        verify(refreshTokenRepository).revokeAllByUser(sampleUser);
    }

    @Test
    @DisplayName("login – persists new refresh token to DB")
    void login_savesRefreshToken() {
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(sampleUser));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        userService.login("john@example.com", "secret123");

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getToken()).isNotBlank();
        assertThat(captor.getValue().isRevoked()).isFalse();
    }

    // ── Refresh ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("refresh – returns new TokenPair for a valid refresh token")
    void refresh_validToken_returnsNewTokenPair() {
        String rawRefreshToken = jwtService.generateRefreshToken(sampleUser);

        RefreshToken stored = new RefreshToken(rawRefreshToken, sampleUser,
                Instant.now().plusSeconds(3600));

        when(refreshTokenRepository.findByToken(rawRefreshToken)).thenReturn(Optional.of(stored));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Optional<UserService.TokenPair> result = userService.refresh(rawRefreshToken);

        assertThat(result).isPresent();
        assertThat(result.get().accessToken()).isNotBlank();
        assertThat(result.get().refreshToken()).isNotBlank();
        // New refresh token should differ from the original
        assertThat(result.get().refreshToken()).isNotEqualTo(rawRefreshToken);
    }

    @Test
    @DisplayName("refresh – returns empty for a JWT with invalid signature")
    void refresh_invalidJwtSignature_returnsEmpty() {
        assertThat(userService.refresh("totally.invalid.jwt")).isEmpty();
    }

    @Test
    @DisplayName("refresh – returns empty when token not found in DB")
    void refresh_tokenNotInDb_returnsEmpty() {
        String rawToken = jwtService.generateRefreshToken(sampleUser);
        when(refreshTokenRepository.findByToken(rawToken)).thenReturn(Optional.empty());

        assertThat(userService.refresh(rawToken)).isEmpty();
    }

    @Test
    @DisplayName("refresh – returns empty and revokes when token is already revoked")
    void refresh_revokedToken_returnsEmpty() {
        String rawToken = jwtService.generateRefreshToken(sampleUser);
        RefreshToken stored = new RefreshToken(rawToken, sampleUser,
                Instant.now().plusSeconds(3600));
        stored.setRevoked(true);

        when(refreshTokenRepository.findByToken(rawToken)).thenReturn(Optional.of(stored));

        assertThat(userService.refresh(rawToken)).isEmpty();
    }

    @Test
    @DisplayName("refresh – returns empty when DB expiry has passed")
    void refresh_expiredDbRecord_returnsEmpty() {
        String rawToken = jwtService.generateRefreshToken(sampleUser);
        // DB expiry in the past
        RefreshToken stored = new RefreshToken(rawToken, sampleUser,
                Instant.now().minusSeconds(1));

        when(refreshTokenRepository.findByToken(rawToken)).thenReturn(Optional.of(stored));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        assertThat(userService.refresh(rawToken)).isEmpty();
        // Must mark it as revoked in DB
        ArgumentCaptor<RefreshToken> cap = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(cap.capture());
        assertThat(cap.getValue().isRevoked()).isTrue();
    }

    // ── Query helpers ─────────────────────────────────────────────────────

    @Test
    @DisplayName("findByEmail – delegates to repository")
    void findByEmail_delegates() {
        when(userRepository.findByEmail("john@example.com")).thenReturn(Optional.of(sampleUser));
        assertThat(userService.findByEmail("john@example.com")).contains(sampleUser);
    }

    @Test
    @DisplayName("findById – delegates to repository")
    void findById_delegates() {
        when(userRepository.findById(sampleUser.getUserId())).thenReturn(Optional.of(sampleUser));
        assertThat(userService.findById(sampleUser.getUserId())).contains(sampleUser);
    }

    @Test
    @DisplayName("getAllUsers – returns all users from repository")
    void getAllUsers_returnsAll() {
        when(userRepository.findAll()).thenReturn(List.of(sampleUser));
        assertThat(userService.getAllUsers()).containsExactly(sampleUser);
    }
}


package com.userservice.service;

import com.userservice.model.RefreshToken;
import com.userservice.model.User;
import com.userservice.repository.RefreshTokenRepository;
import com.userservice.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository         userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BCryptPasswordEncoder  passwordEncoder;
    private final JwtService             jwtService;

    public UserService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       BCryptPasswordEncoder passwordEncoder,
                       JwtService jwtService) {
        this.userRepository         = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder        = passwordEncoder;
        this.jwtService             = jwtService;
    }

    // ── Register ──────────────────────────────────────────────────────────

    @Transactional
    public User register(String name, String email, String password) {
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("user");
        User saved = userRepository.save(user);
        System.out.println("[UserService] Registered → " + email);
        return saved;
    }

    // ── Login ─────────────────────────────────────────────────────────────

    /**
     * Validates credentials, revokes old refresh tokens, and issues
     * a fresh access + refresh token pair.
     *
     * @return token pair record, or empty if credentials are invalid
     */
    @Transactional
    public Optional<TokenPair> login(String email, String rawPassword) {
        Optional<User> optional = userRepository.findByEmail(email);
        if (optional.isEmpty()) return Optional.empty();

        User user = optional.get();
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            return Optional.empty();
        }

        // Revoke any existing refresh tokens for this user
        refreshTokenRepository.revokeAllByUser(user);

        String accessToken  = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        Instant expiryDate = Instant.now()
                .plusMillis(jwtService.getRefreshExpirationMs());
        refreshTokenRepository.save(
                new RefreshToken(refreshToken, user, expiryDate));

        return Optional.of(new TokenPair(accessToken, refreshToken,
                jwtService.getAccessExpirationMs() / 1000,
                user));
    }

    // ── Refresh Token ─────────────────────────────────────────────────────

    /**
     * Validates a refresh token and issues a new access token.
     * Rotates the refresh token (old one is revoked, new one is issued).
     */
    @Transactional
    public Optional<TokenPair> refresh(String rawRefreshToken) {
        // 1. Validate JWT signature / expiry
        if (!jwtService.isTokenValid(rawRefreshToken)) {
            return Optional.empty();
        }

        // 2. Look up in DB
        Optional<RefreshToken> stored = refreshTokenRepository.findByToken(rawRefreshToken);
        if (stored.isEmpty()) return Optional.empty();

        RefreshToken rt = stored.get();

        // 3. Check revoked flag and DB expiry
        if (rt.isRevoked() || rt.getExpiryDate().isBefore(Instant.now())) {
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
            return Optional.empty();
        }

        // 4. Rotate: revoke old, issue new
        rt.setRevoked(true);
        refreshTokenRepository.save(rt);

        User user = rt.getUser();
        String newAccessToken  = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        Instant expiryDate = Instant.now()
                .plusMillis(jwtService.getRefreshExpirationMs());
        refreshTokenRepository.save(
                new RefreshToken(newRefreshToken, user, expiryDate));

        return Optional.of(new TokenPair(newAccessToken, newRefreshToken,
                jwtService.getAccessExpirationMs() / 1000, user));
    }

    // ── Query helpers ─────────────────────────────────────────────────────

    public Optional<User> findByEmail(String email)  { return userRepository.findByEmail(email); }
    public Optional<User> findById(String id)         { return userRepository.findById(id);       }
    public List<User>     getAllUsers()                { return userRepository.findAll();           }

    // ── Inner record ──────────────────────────────────────────────────────

    public record TokenPair(
            String accessToken,
            String refreshToken,
            long   expiresInSeconds,
            User   user) {}
}
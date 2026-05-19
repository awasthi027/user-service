package com.userservice.service;

import com.userservice.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

/**
 * Handles JWT creation and validation.
 *
 * Access tokens are short-lived (default 15 min) and carry the standard
 * claims expected by an API Gateway: sub, iss, aud, iat, exp, jti, role.
 *
 * Refresh tokens are long-lived (default 7 days) and are stored (hashed)
 * in the database so they can be revoked.
 */
@Service
public class JwtService {

    private final SecretKey   key;
    private final long        accessExpirationMs;
    private final long        refreshExpirationMs;
    private final String      issuer;
    private final String      audience;

    public JwtService(
            @Value("${jwt.secret}")              String secret,
            @Value("${jwt.expiration-ms:43200000}")        long   accessExpirationMs,
            @Value("${jwt.refresh-expiration-ms:604800000}") long refreshExpirationMs,
            @Value("${jwt.issuer:user-service}")  String issuer,
            @Value("${jwt.audience:api-gateway}") String audience) {

        this.key                 = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessExpirationMs  = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
        this.issuer              = issuer;
        this.audience            = audience;
    }

    // ── Access Token ──────────────────────────────────────────────────────

    /** Generates a signed JWT access token with API-Gateway-compatible claims. */
    public String generateAccessToken(User user) {
        Date now    = new Date();
        Date expiry = new Date(now.getTime() + accessExpirationMs);

        return Jwts.builder()
                .subject(user.getUserId())
                .claim("email", user.getEmail())
                .claim("role",  user.getRole())
                .issuer(issuer)
                .audience().add(audience).and()
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key)
                .compact();
    }

    /** Generates a signed JWT refresh token (no role / audience claims needed). */
    public String generateRefreshToken(User user) {
        Date now    = new Date();
        Date expiry = new Date(now.getTime() + refreshExpirationMs);

        return Jwts.builder()
                .subject(user.getUserId())
                .issuer(issuer)
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key)
                .compact();
    }

    // ── Validation helpers ────────────────────────────────────────────────

    /**
     * Parses and validates the token signature + expiration.
     *
     * @return parsed {@link Claims}
     * @throws JwtException if the token is invalid or expired
     */
    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUserId(String token) {
        return validateAndGetClaims(token).getSubject();
    }

    public boolean isTokenValid(String token) {
        try {
            validateAndGetClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // ── Accessors used in tests ───────────────────────────────────────────
    public long getAccessExpirationMs()  { return accessExpirationMs;  }
    public long getRefreshExpirationMs() { return refreshExpirationMs; }
    public String getIssuer()            { return issuer;              }
    public String getAudience()          { return audience;            }
}


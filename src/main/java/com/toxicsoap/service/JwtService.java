package com.toxicsoap.service;

import com.toxicsoap.config.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final SecretKey secretKey;
    private final long expirationMs;
    private final String issuer;

    public JwtService(AuthProperties authProperties) {
        AuthProperties.JwtConfig jwtConfig = authProperties.getJwt();
        this.secretKey = Keys.hmacShaKeyFor(
            jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)
        );
        this.expirationMs = jwtConfig.getExpirationMs();
        this.issuer = jwtConfig.getIssuer();
    }

    /**
     * Generate a JWT token for a user.
     *
     * @param username the username to include as subject
     * @param role the user's role to include as claim
     * @return the signed JWT token string
     */
    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
            .subject(username)
            .claim("role", role)
            .issuer(issuer)
            .issuedAt(now)
            .expiration(expiry)
            .signWith(secretKey)
            .compact();
    }

    /**
     * Parse and validate a JWT token.
     *
     * @param token the JWT token string
     * @return Optional containing JwtClaims if valid, empty if invalid or expired
     */
    public Optional<JwtClaims> parseToken(String token) {
        try {
            Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();

            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            if (username == null || role == null) {
                logger.debug("JWT missing required claims");
                return Optional.empty();
            }

            return Optional.of(new JwtClaims(username, role));

        } catch (JwtException e) {
            logger.debug("JWT validation failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Record to hold parsed JWT claims.
     */
    public record JwtClaims(String username, String role) {}
}

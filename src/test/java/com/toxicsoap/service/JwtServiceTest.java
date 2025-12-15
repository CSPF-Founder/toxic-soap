package com.toxicsoap.service;

import com.toxicsoap.config.AuthProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private AuthProperties authProperties;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        authProperties = new AuthProperties();

        // Configure test users
        AuthProperties.UserConfig user = new AuthProperties.UserConfig();
        user.setUsername("testuser");
        user.setPassword("testpass");
        user.setRole("USER");

        AuthProperties.UserConfig admin = new AuthProperties.UserConfig();
        admin.setUsername("testadmin");
        admin.setPassword("adminpass");
        admin.setRole("ADMIN");

        authProperties.setUsers(List.of(user, admin));

        // Configure JWT
        AuthProperties.JwtConfig jwtConfig = new AuthProperties.JwtConfig();
        jwtConfig.setSecret("test-secret-key-for-jwt-testing-minimum-32-characters-long");
        jwtConfig.setExpirationMs(3600000);
        jwtConfig.setIssuer("test-issuer");
        authProperties.setJwt(jwtConfig);

        // Configure API keys
        AuthProperties.ApiKeyConfig apiKey = new AuthProperties.ApiKeyConfig();
        apiKey.setKey("test-api-key-123");
        apiKey.setUsername("testuser");
        apiKey.setRole("USER");
        authProperties.setApiKeys(List.of(apiKey));

        jwtService = new JwtService(authProperties);
    }

    @Test
    void testGenerateToken_returnsNonEmptyToken() {
        String token = jwtService.generateToken("testuser", "USER");

        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(token.contains(".")); // JWT format: header.payload.signature
    }

    @Test
    void testGenerateToken_differentUsersGetDifferentTokens() {
        String userToken = jwtService.generateToken("testuser", "USER");
        String adminToken = jwtService.generateToken("testadmin", "ADMIN");

        assertNotEquals(userToken, adminToken);
    }

    @Test
    void testParseToken_validToken_returnsCorrectClaims() {
        String token = jwtService.generateToken("testuser", "USER");

        Optional<JwtService.JwtClaims> claims = jwtService.parseToken(token);

        assertTrue(claims.isPresent());
        assertEquals("testuser", claims.get().username());
        assertEquals("USER", claims.get().role());
    }

    @Test
    void testParseToken_invalidToken_returnsEmpty() {
        Optional<JwtService.JwtClaims> claims = jwtService.parseToken("invalid.token.here");

        assertTrue(claims.isEmpty());
    }

    @Test
    void testParseToken_tamperedToken_returnsEmpty() {
        String token = jwtService.generateToken("testuser", "USER");
        // Tamper with the token by changing a character
        String tamperedToken = token.substring(0, token.length() - 5) + "xxxxx";

        Optional<JwtService.JwtClaims> claims = jwtService.parseToken(tamperedToken);

        assertTrue(claims.isEmpty());
    }

    @Test
    void testParseToken_emptyToken_returnsEmpty() {
        Optional<JwtService.JwtClaims> claims = jwtService.parseToken("");

        assertTrue(claims.isEmpty());
    }

    @Test
    void testParseToken_nullToken_returnsEmpty() {
        Optional<JwtService.JwtClaims> claims = jwtService.parseToken(null);

        assertTrue(claims.isEmpty());
    }

    @Test
    void testGenerateAndParseToken_adminRole() {
        String token = jwtService.generateToken("testadmin", "ADMIN");

        Optional<JwtService.JwtClaims> claims = jwtService.parseToken(token);

        assertTrue(claims.isPresent());
        assertEquals("testadmin", claims.get().username());
        assertEquals("ADMIN", claims.get().role());
    }

    @Test
    void testJwtClaimsRecord() {
        JwtService.JwtClaims claims = new JwtService.JwtClaims("user", "ROLE");

        assertEquals("user", claims.username());
        assertEquals("ROLE", claims.role());
    }
}

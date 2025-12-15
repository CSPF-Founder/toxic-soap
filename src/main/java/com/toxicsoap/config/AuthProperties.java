package com.toxicsoap.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "toxic-soap.auth")
public class AuthProperties {

    private List<UserConfig> users = new ArrayList<>();
    private JwtConfig jwt = new JwtConfig();
    private List<ApiKeyConfig> apiKeys = new ArrayList<>();

    public List<UserConfig> getUsers() {
        return users;
    }

    public void setUsers(List<UserConfig> users) {
        this.users = users;
    }

    public JwtConfig getJwt() {
        return jwt;
    }

    public void setJwt(JwtConfig jwt) {
        this.jwt = jwt;
    }

    public List<ApiKeyConfig> getApiKeys() {
        return apiKeys;
    }

    public void setApiKeys(List<ApiKeyConfig> apiKeys) {
        this.apiKeys = apiKeys;
    }

    public static class UserConfig {
        private String username;
        private String password;
        private String role;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }

    public static class JwtConfig {
        private String secret = "default-secret-key-change-in-production-min-32-chars";
        private long expirationMs = 3600000; // 1 hour
        private String issuer = "toxic-soap";

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public long getExpirationMs() {
            return expirationMs;
        }

        public void setExpirationMs(long expirationMs) {
            this.expirationMs = expirationMs;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
    }

    public static class ApiKeyConfig {
        private String key;
        private String username;
        private String role;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }
}
